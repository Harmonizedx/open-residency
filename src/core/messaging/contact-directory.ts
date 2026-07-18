import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import axios from 'axios';
import { ContactDirectory } from './types';

/**
 * Turning a residentId into a dialable number, without keeping a plaintext phone book.
 *
 * There is a real tension here and it is worth stating plainly. The register deliberately
 * stores only a `phoneHash`, which is one-way -- excellent for privacy, and useless for
 * delivery. So a system that actually sends the one-time code has to hold the number in
 * some recoverable form somewhere. The question is only where, and under what key.
 *
 * Two answers are offered, and a deployment picks:
 *
 *   NONE      No directory. OTP delivery is disabled and the sign-in fallback is off.
 *             Honest default for a deployment that has not decided yet -- better than a
 *             stub that silently pretends to send.
 *
 *   ENCRYPTED The number is stored on the resident row under AES-256-GCM with a key held
 *             outside the database (CONTACT_ENCRYPTION_KEY, ideally from a KMS). A dump of
 *             the database yields ciphertext. The phoneHash stays alongside it and remains
 *             what lookups and USSD matching use, so nothing else in the system gains
 *             access to the plaintext.
 *
 *   EXTERNAL  The number is not stored here at all. A directory the ministry already runs
 *             (the civil register's contact service, an MNO lookup) answers residentId ->
 *             msisdn over an authenticated call. Strongest option: OpenResidency holds no
 *             recoverable contact data, and the directory's own access log records every
 *             resolution.
 *
 * EXTERNAL is the right answer for a national deployment. ENCRYPTED is the pragmatic one
 * for a state pilot with no such service yet.
 */

export type ContactDirectoryMode = 'none' | 'encrypted' | 'external';

export interface ExternalDirectoryConfig {
  baseUrl: string;
  /** Path with a {residentId} placeholder. */
  path: string;
  /** Dot-path to the E.164 number in the response. */
  responsePath: string;
  secretEnv?: string;
  headerName?: string;
  timeoutMs?: number;
}

/** No contact data available: OTP delivery is switched off rather than faked. */
export class NullContactDirectory implements ContactDirectory {
  async lookup(): Promise<string | null> {
    return null;
  }
}

// ---- envelope encryption for stored numbers -------------------------------

/**
 * The encryption key. Derived from CONTACT_ENCRYPTION_KEY, which must be a 32-byte hex
 * value in production. Deriving through SHA-256 means a shorter operator-supplied value
 * still yields a valid key length, but it does NOT add entropy -- the deploy docs ask for
 * `openssl rand -hex 32` for that reason.
 */
function contactKey(): Buffer | null {
  const raw = process.env.CONTACT_ENCRYPTION_KEY;
  if (!raw) return null;
  return createHash('sha256').update(raw).digest();
}

/** AES-256-GCM. Returns `v1.<ivB64>.<tagB64>.<ctB64>`; GCM's tag is what detects tampering. */
export function encryptContact(e164: string): string {
  const key = contactKey();
  if (!key) throw new Error('CONTACT_ENCRYPTION_KEY is not set; cannot store a contact number');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(e164, 'utf8'), cipher.final()]);
  return `v1.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${ct.toString('base64url')}`;
}

export function decryptContact(blob: string): string | null {
  const key = contactKey();
  if (!key) return null;
  const [version, ivB64, tagB64, ctB64] = blob.split('.');
  if (version !== 'v1' || !ivB64 || !tagB64 || !ctB64) return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(ctB64, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    // Wrong key or tampered ciphertext. Treated as "no number known" rather than throwing,
    // so a key rotation in progress degrades to no-delivery instead of a 500 on sign-in.
    return null;
  }
}

/** Reads the encrypted number off the resident row. */
export class EncryptedColumnContactDirectory implements ContactDirectory {
  constructor(private loadEncrypted: (residentId: string) => Promise<string | null>) {}

  async lookup(residentId: string): Promise<string | null> {
    const blob = await this.loadEncrypted(residentId);
    return blob ? decryptContact(blob) : null;
  }
}

/** Asks a contact service the deployment already runs. */
export class ExternalContactDirectory implements ContactDirectory {
  constructor(private cfg: ExternalDirectoryConfig) {}

  async lookup(residentId: string): Promise<string | null> {
    const secret = this.cfg.secretEnv ? process.env[this.cfg.secretEnv] : undefined;
    if (this.cfg.secretEnv && !secret) {
      throw new Error(
        `Contact directory secret ${this.cfg.secretEnv} is not set in the environment`,
      );
    }
    try {
      const res = await axios.get(
        `${this.cfg.baseUrl.replace(/\/$/, '')}${this.cfg.path.replace('{residentId}', encodeURIComponent(residentId))}`,
        {
          timeout: this.cfg.timeoutMs ?? 5_000,
          headers: secret ? { [this.cfg.headerName ?? 'x-api-key']: secret } : {},
        },
      );
      const value = this.cfg.responsePath
        .split('.')
        .reduce<unknown>(
          (acc, k) =>
            acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined,
          res.data,
        );
      return typeof value === 'string' && value.length > 0 ? value : null;
    } catch {
      // A directory outage must not become an enumeration oracle, so a failure is
      // indistinguishable from "no number on file" to the caller.
      return null;
    }
  }
}
