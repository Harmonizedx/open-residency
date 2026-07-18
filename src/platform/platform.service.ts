import { Injectable, Logger } from '@nestjs/common';
import { join } from 'node:path';
import { JWK } from 'jose';
import { CountryConfig, loadCountryConfigs } from '../core/config/country-config';
import { ProviderRegistry } from '../core/foundational/registry';
import { KeyStore, IssuerKey } from '../core/credentials/keystore';
import { VcIssuer } from '../core/credentials/vc-issuer';
import { LdpIssuer } from '../core/credentials/ldp-issuer';
import { residencyContextDocument } from '../core/credentials/jsonld/document-loader';
import { VcVerifier, TrustedIssuer } from '../core/credentials/vc-verifier';
import { buildDidWebDocument } from '../core/credentials/did';
import { ResidencyService } from '../core/residency/residency-service';
import { Oid4vciService } from '../core/oid4vci/oid4vci-service';
import { Oid4vpService } from '../core/oid4vp/oid4vp-service';
import { OtpService, OtpSender } from '../core/sso/otp';
import { SsoAuthService } from '../core/sso/sso-auth';
import { OperatorService } from '../core/operator/operator';
import { FederatedOperatorVerifier } from '../core/operator/federated';
import { OperatorSessions } from '../core/operator/session';
import { buildMessagingProvider } from '../core/messaging/providers';
import { MessagingOtpSender } from '../core/messaging/otp-sender';
import { ContactDirectory, MessagingProvider } from '../core/messaging/types';
import {
  EncryptedColumnContactDirectory,
  ExternalContactDirectory,
  NullContactDirectory,
} from '../core/messaging/contact-directory';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../core/oid4vp/vp-verifier';
import { AuditLog } from '../core/audit/audit-log';
import { ConsentService } from '../core/consent/consent';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOtpStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
} from '../prisma/prisma.service';
import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Everything the OperatorGuard needs to authenticate a member of staff, assembled once at
 * boot from `operatorAuth` in the default country config.
 */
export interface OperatorAuthContext {
  mode: 'oidc' | 'local' | 'sharedKey';
  operators: OperatorService;
  federated?: FederatedOperatorVerifier;
  sessions?: OperatorSessions;
  sharedKeyMatches(presented: string): boolean;
}

/**
 * Central wiring for the framework-agnostic core. Holds the loaded country configs,
 * the issuer key, the issuer/verifier, and the residency orchestration, and exposes
 * them to the thin Nest controllers.
 */
@Injectable()
export class PlatformService {
  private readonly log = new Logger('Platform');
  private configs!: Map<string, CountryConfig>;
  private key!: IssuerKey;
  private registry!: ProviderRegistry;
  private issuer!: VcIssuer;
  private ldpIssuer!: LdpIssuer;
  private verifier!: VcVerifier;
  private residency!: ResidencyService;
  private oid4vci!: Oid4vciService;
  private oid4vp!: Oid4vpService;
  private vpVerifier!: VpVerifier;
  private ssoAuth!: SsoAuthService;
  private audit!: AuditLog;
  private consent!: ConsentService;
  private platformIssuerDid!: string;
  private trust = new Map<string, TrustedIssuer>();
  private operatorAuth!: OperatorAuthContext;
  private messaging?: MessagingProvider;
  private contacts!: ContactDirectory;
  private pepper!: string;

  constructor(
    private store: PrismaResidencyStore,
    private auditStore: PrismaAuditStore,
    private consentStore: PrismaConsentStore,
    private oid4vciStore: PrismaOid4vciStore,
    private oid4vpStore: PrismaOid4vpStore,
    private otpStore: PrismaOtpStore,
    private operatorStore: PrismaOperatorStore,
  ) {}

  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    const dir = process.env.COUNTRY_CONFIG_DIR ?? join(process.cwd(), 'config/countries');
    this.configs = loadCountryConfigs(dir);
    this.log.log(`Loaded ${this.configs.size} country config(s): ${[...this.configs.keys()].join(', ')}`);

    // Issuer key: from env JWK in production (KMS-exported / sealed), generated in dev.
    const jwkEnv = process.env.ISSUER_PRIVATE_JWK;
    if (jwkEnv) {
      const jwk = JSON.parse(jwkEnv) as JWK;
      this.key = await KeyStore.fromJwk(jwk, process.env.ISSUER_KID ?? 'issuer-key-1');
    } else {
      this.key = await KeyStore.generate(process.env.ISSUER_KID ?? 'issuer-key-1');
      this.log.warn('No ISSUER_PRIVATE_JWK set: generated an ephemeral dev key. Do NOT use in production.');
    }

    // Subject pepper: the HMAC key that makes a subjectRef non-reversible and
    // non-correlatable across deployments. Falling back silently is the worst case -- the
    // default is in the public source, so every subjectRef becomes reproducible by anyone
    // and the whole tokenization design is void. Warn as loudly as the issuer key does.
    const pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper';
    if (!process.env.SUBJECT_PEPPER) {
      this.log.warn(
        'No SUBJECT_PEPPER set: using the well-known dev pepper. Subject references are ' +
          'reproducible by anyone with the source. Do NOT use in production.',
      );
    }
    this.pepper = pepper;
    this.registry = new ProviderRegistry(pepper);
    this.issuer = new VcIssuer(this.key);
    this.ldpIssuer = new LdpIssuer(this.key);
    this.residency = new ResidencyService(
      this.registry,
      this.issuer,
      this.store,
      (cfg) => this.statusListUrl(cfg),
      this.ldpIssuer,
    );

    // OpenID4VCI: the standards-based issuance path that lets a citizen's own wallet
    // pull a credential bound to a key on their device.
    this.oid4vci = new Oid4vciService(
      { credentialIssuer: this.publicBaseUrl() },
      () => this.listConfigs(),
      (countryCode) => this.getConfig(countryCode),
      this.residency,
      this.store,
      this.oid4vciStore,
      this.key,
    );

    // Trust ourselves as an issuer for the verify endpoint (each config's issuerDid
    // maps to our public key). In a federation, other issuers' keys are added here.
    for (const cfg of this.configs.values()) {
      this.trust.set(cfg.credential.issuerDid, {
        did: cfg.credential.issuerDid,
        publicJwk: this.key.publicJwk,
        statusLists: {},
      });
    }
    this.verifier = new VcVerifier(this.trust);

    // OpenID4VP: the presentation half. The VP verifier reuses the VC verifier -- and
    // therefore its status-list cache -- so a revoked resident is revoked whether the
    // credential arrives as a VC-JWT or as JSON-LD.
    const ldpTrust = new Map<string, VpTrustedIssuer>();
    for (const cfg of this.configs.values()) {
      ldpTrust.set(cfg.credential.issuerDid, {
        did: cfg.credential.issuerDid,
        publicKeyObject: keyObjectFromJwk(this.key.publicJwk),
      });
    }
    this.vpVerifier = new VpVerifier(this.verifier, ldpTrust);
    // OpenID4VP is deployment-wide (a presentation request names no country), so its
    // profile is read from the default -- that is, the first -- country config.
    const defaultCfg = this.listConfigs()[0];
    this.oid4vp = new Oid4vpService(
      {
        baseUrl: this.publicBaseUrl(),
        // The verifier identifies itself by DID so a wallet can resolve our key and check
        // the request object's signature without a PKI or a network round-trip.
        clientId: defaultCfg?.credential.issuerDid ?? 'did:web:openresidency.example',
        clientName: defaultCfg?.credential.issuerName ?? 'OpenResidency Verifier',
        requestTtlSeconds: defaultCfg?.presentation.requestTtlSeconds ?? 300,
        query: defaultCfg?.presentation.query ?? ['dcql', 'presentation_definition'],
      },
      this.oid4vpStore,
      () => this.vpVerifier,
      this.key,
    );

    // Sign-in authentication: a Verifiable Presentation as the strong factor, a one-time
    // code as the fallback. Both halves of the fallback are configured, not stubbed --
    // the aggregator that carries the message, and the directory that turns a residentId
    // into a number to carry it to.
    this.contacts = this.buildContactDirectory(defaultCfg);
    this.messaging = this.buildMessaging(defaultCfg);
    const otp = new OtpService(this.otpStore, this.buildOtpSender(defaultCfg), () =>
      crypto.randomUUID(),
    );
    this.ssoAuth = new SsoAuthService(this.oid4vp, otp, this.store);

    // Operator identity for privileged routes.
    this.operatorAuth = this.buildOperatorAuth(defaultCfg);
    await this.bootstrapOperator();

    // Audit and consent frameworks.
    this.platformIssuerDid =
      process.env.PLATFORM_ISSUER_DID ??
      this.listConfigs()[0]?.credential.issuerDid ??
      'did:web:openresidency.example';
    this.audit = new AuditLog(this.auditStore);
    this.consent = new ConsentService(this.consentStore, this.key, this.platformIssuerDid);
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

  private buildOtpSender(cfg?: CountryConfig): OtpSender {
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
    return this.listConfigs()[0]?.contactDirectory.mode ?? 'none';
  }

  // ---- operator identity --------------------------------------------------

  private buildOperatorAuth(cfg?: CountryConfig): OperatorAuthContext {
    const conf = cfg?.operatorAuth ?? {
      mode: 'sharedKey' as const,
      issuerName: 'OpenResidency',
      local: { requireMfa: true, sessionTtlSeconds: 8 * 3600 },
    };
    const operators = new OperatorService(this.operatorStore, {
      requireMfa: conf.local.requireMfa,
      issuerName: conf.issuerName,
    });

    const ctx: OperatorAuthContext = {
      mode: conf.mode,
      operators,
      sharedKeyMatches: (presented: string) => {
        const required = process.env.ADMIN_API_KEY;
        if (!required) return false;
        // Hash both sides to a fixed length first: timingSafeEqual throws on a length
        // mismatch, which would itself leak the key's length.
        const a = createHash('sha256').update(presented).digest();
        const b = createHash('sha256').update(required).digest();
        return timingSafeEqual(a, b);
      },
    };

    if (conf.mode === 'oidc') {
      ctx.federated = new FederatedOperatorVerifier({
        issuer: conf.oidc!.issuer,
        audience: conf.oidc!.audience,
        roleClaim: conf.oidc!.roleClaim,
        nameClaim: conf.oidc!.nameClaim,
        roleMap: conf.oidc!.roleMap,
        jwksUri: conf.oidc!.jwksUri,
      });
      this.log.log(`Operator auth: OIDC (issuer ${conf.oidc!.issuer})`);
    } else if (conf.mode === 'local') {
      ctx.sessions = new OperatorSessions(
        this.key.privateKey,
        this.key.publicKey,
        this.publicBaseUrl(),
        conf.local.sessionTtlSeconds,
      );
      this.log.log(
        `Operator auth: local accounts (MFA ${conf.local.requireMfa ? 'required' : 'optional'})`,
      );
    } else {
      this.log.warn(
        'Operator auth: shared ADMIN_API_KEY. This carries no operator identity, so every ' +
          'privileged action audits to the same actor, there are no roles, and rotation ' +
          'requires a restart. Set operatorAuth.mode to `oidc` before government staff use ' +
          'this deployment.',
      );
    }
    return ctx;
  }

  /**
   * Create the first admin from the environment, once, if no operators exist.
   *
   * Without this there is no way into a `local` deployment: every operator-management
   * route requires an operator. The TOTP secret is logged exactly once, on the boot that
   * creates the account, because there is nowhere else for it to go -- and the account is
   * useless without it.
   */
  private async bootstrapOperator(): Promise<void> {
    const email = process.env.OPERATOR_BOOTSTRAP_EMAIL;
    const password = process.env.OPERATOR_BOOTSTRAP_PASSWORD;
    if (!email || !password) return;
    if ((await this.operatorAuth.operators.count()) > 0) return;
    const { totpSecret, totpUri } = await this.operatorAuth.operators.createOperator({
      email,
      displayName: email,
      roles: ['admin'],
      password,
    });
    this.log.warn(
      `Bootstrapped the first operator account ${email} with the admin role. ` +
        `Enrol this TOTP secret in an authenticator app now -- it is not shown again: ${totpSecret}`,
    );
    this.log.warn(`Enrolment URI: ${totpUri}`);
  }

  getOperatorAuth(): OperatorAuthContext {
    return this.operatorAuth;
  }

  /**
   * The HMAC key behind every pseudonym this deployment issues -- foundational subject
   * references and pairwise OIDC subjects alike. One pepper, so there is a single secret
   * to protect and a single rotation to reason about.
   */
  getSubjectPepper(): string {
    return this.pepper;
  }

  /**
   * The public origin of this deployment. It doubles as the OpenID4VCI Credential Issuer
   * Identifier, which is what a wallet's key proof must name in its `aud` -- so if this
   * is misconfigured, every proof is rejected as audience-mismatched.
   */
  publicBaseUrl(): string {
    return (process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000').replace(/\/$/, '');
  }

  statusListUrl(cfg: CountryConfig): string {
    return `${this.publicBaseUrl()}/.well-known/status/${cfg.countryCode.toLowerCase()}.json`;
  }

  /** The residency JSON-LD context document, published for external verifiers. */
  residencyContext(): unknown {
    return residencyContextDocument();
  }

  getConfig(countryCode: string): CountryConfig | undefined {
    return this.configs.get(countryCode.toUpperCase());
  }
  listConfigs(): CountryConfig[] {
    return [...this.configs.values()];
  }
  getResidency(): ResidencyService {
    return this.residency;
  }
  getOid4vci(): Oid4vciService {
    return this.oid4vci;
  }
  getOid4vp(): Oid4vpService {
    return this.oid4vp;
  }
  getSsoAuth(): SsoAuthService {
    return this.ssoAuth;
  }
  getLdpIssuer(): LdpIssuer {
    return this.ldpIssuer;
  }
  getVerifier(): VcVerifier {
    return this.verifier;
  }
  getStore(): PrismaResidencyStore {
    return this.store;
  }
  getAudit(): AuditLog {
    return this.audit;
  }
  getConsent(): ConsentService {
    return this.consent;
  }
  getIssuerKey(): IssuerKey {
    return this.key;
  }

  didDocument(countryCode: string): Record<string, unknown> | undefined {
    const cfg = this.getConfig(countryCode);
    if (!cfg) return undefined;
    return buildDidWebDocument(cfg.credential.issuerDid, this.key.publicJwk);
  }

  /** Refresh the verifier's cached status list for a country from the store. */
  async syncStatusList(cfg: CountryConfig): Promise<void> {
    const list = await this.store.loadStatusList(cfg.countryCode);
    const t = this.trust.get(cfg.credential.issuerDid);
    if (t) t.statusLists = { [this.statusListUrl(cfg)]: list };
  }
}
