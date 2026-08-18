// SPDX-License-Identifier: Apache-2.0
import { Logger } from '@nestjs/common';
import { CountryConfig } from '../core/config/country-config';
import { OtpSender } from '../core/sso/otp';
import { buildMessagingProvider } from '../core/messaging/providers';
import { MessagingOtpSender } from '../core/messaging/otp-sender';
import { ContactDirectory, MessagingProvider } from '../core/messaging/types';
import {
  EncryptedColumnContactDirectory,
  ExternalContactDirectory,
  NullContactDirectory,
} from '../core/messaging/contact-directory';
import { PrismaResidencyStore } from '../prisma/prisma.service';

/**
 * Reaching a resident: which aggregator carries the message, and how a residentId becomes a
 * number to carry it to.
 *
 * Two halves that are always configured together and useless apart -- a provider with no
 * directory has nowhere to send, a directory with no provider has nothing to send with --
 * so they are assembled and held together rather than as two fields on a class that also
 * does everything else.
 *
 * The privacy boundary lives here and is the reason the directory is a strategy rather than
 * a column read: this deployment may hold no plaintext number at all, may hold one encrypted
 * under a key outside the database, or may resolve it from an external system at send time.
 * Everything above this point works with a residentId and never sees a phone number.
 */
export class ResidentMessaging {
  private readonly log = new Logger('Messaging');
  private contacts!: ContactDirectory;
  private messaging?: MessagingProvider;
  private defaultCfg?: CountryConfig;

  constructor(private store: PrismaResidencyStore) {}

  /** Assemble the directory and the provider from the deployment's default config. */
  init(cfg?: CountryConfig): void {
    this.defaultCfg = cfg;
    this.contacts = this.buildContactDirectory(cfg);
    this.messaging = this.buildMessaging(cfg);
  }

  /** The directory, for callers that resolve a contact themselves. */
  getContacts(): ContactDirectory {
    return this.contacts;
  }


  // ---- messaging ----------------------------------------------------------

  /**
   * Where a resident's phone number comes from at send time.
   *
   * `none` is the default and disables OTP delivery outright. That is deliberate: the
   * previous behaviour was to "deliver" every code to the service log, which looks like a
   * working fallback factor and is not one. A deployment that has not decided where
   * contact data lives should have a sign-in fallback that is visibly off, not silently
   * broken.
   */
  private buildContactDirectory(cfg?: CountryConfig): ContactDirectory {
    const dir = cfg?.contactDirectory;
    if (!dir || dir.mode === 'none') return new NullContactDirectory();
    if (dir.mode === 'external') {
      this.log.log(`Contact directory: external (${dir.external!.baseUrl})`);
      return new ExternalContactDirectory(dir.external!);
    }
    if (!process.env.CONTACT_ENCRYPTION_KEY) {
      // Fail closed rather than run with a directory that can never decrypt anything: a
      // silently empty directory is indistinguishable from "this citizen has no phone".
      throw new Error(
        'contactDirectory.mode is `encrypted` but CONTACT_ENCRYPTION_KEY is not set. ' +
          'Generate one with `openssl rand -hex 32`.',
      );
    }
    this.log.log('Contact directory: encrypted column');
    return new EncryptedColumnContactDirectory((residentId) =>
      this.store.loadEncryptedContact(residentId),
    );
  }

  private buildMessaging(cfg?: CountryConfig): MessagingProvider | undefined {
    const m = cfg?.messaging;
    if (!m) {
      this.log.warn(
        'No messaging provider configured: one-time codes cannot be delivered, so the ' +
          'OTP sign-in fallback is disabled. Configure `messaging` in the country config.',
      );
      return undefined;
    }
    if (m.provider === 'LOG') {
      this.log.warn(
        'Messaging provider is LOG: one-time codes are written to the service log and ' +
          'NOT delivered. Development only.',
      );
    } else {
      this.log.log(`Messaging provider: ${m.provider}`);
    }
    return buildMessagingProvider({
      provider: m.provider,
      baseUrl: m.baseUrl,
      sender: m.sender,
      timeoutMs: m.timeoutMs,
      auth: m.auth,
      request: m.request,
    });
  }

  /** The OTP sender the SSO layer signs residents in with. */
  buildOtpSender(cfg?: CountryConfig): OtpSender {
    const provider = this.messaging;
    const contacts = this.contacts;
    if (!provider) {
      // No aggregator: refuse to issue rather than pretend. The interaction controller
      // still answers the citizen identically either way, so this does not leak whether a
      // residency ID exists.
      return {
        async send(): Promise<{ channel: string }> {
          throw new Error('MESSAGING_NOT_CONFIGURED');
        },
      };
    }
    return new MessagingOtpSender(
      provider,
      contacts,
      cfg?.messaging?.otpTemplate,
      cfg?.credential.issuerName ?? 'OpenResidency',
    );
  }

  /** Send a non-OTP notification (USSD status replies). No-op when messaging is unconfigured. */
  async notify(residentId: string, body: string): Promise<boolean> {
    if (!this.messaging) return false;
    const to = await this.contacts.lookup(residentId);
    if (!to) return false;
    try {
      await this.messaging.send({ to, body, kind: 'notification' });
      return true;
    } catch (e) {
      this.log.warn(`Notification to resident ${residentId} failed: ${(e as Error).message}`);
      return false;
    }
  }

  messagingConfigured(): boolean {
    return !!this.messaging;
  }

  /** Which contact-storage policy this deployment runs, so enrolment keeps the right fields. */
  contactDirectoryMode(): 'none' | 'encrypted' | 'external' {
    return this.defaultCfg?.contactDirectory.mode ?? 'none';
  }
}
