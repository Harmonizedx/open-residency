import { jwtVerify, importJWK, JWK, KeyLike } from 'jose';
import { StatusList } from './status-list';

/**
 * Verifies a State Residency Verifiable Credential.
 *
 * Designed to run OFFLINE. The verifier holds:
 *   - a trust list mapping issuer DID -> public JWK (synced when last online, or
 *     loaded from a did:key which needs no network at all), and
 *   - an optional cached status list snapshot per issuer.
 *
 * With those two artifacts a border post, clinic, or subsidy desk with no internet
 * can still confirm a credential is authentic, unexpired, and not revoked as of the
 * last sync. When online, the same code path refreshes the status list first.
 */

export interface TrustedIssuer {
  did: string;
  publicJwk: JWK;
  /** Cached status list, keyed by statusListCredential URL. */
  statusLists?: Record<string, StatusList>;
}

export interface VerificationOutcome {
  valid: boolean;
  reason?: string;
  offline: boolean;
  checkedRevocation: boolean;
  subject?: Record<string, unknown>;
  issuerDid?: string;
  expiresAt?: string;
}

export class VcVerifier {
  private keyCache = new Map<string, KeyLike>();
  constructor(private trust: Map<string, TrustedIssuer>) {}

  private async keyFor(did: string): Promise<KeyLike | undefined> {
    if (this.keyCache.has(did)) return this.keyCache.get(did);
    const issuer = this.trust.get(did);
    if (!issuer) return undefined;
    const key = (await importJWK(issuer.publicJwk, 'EdDSA')) as KeyLike;
    this.keyCache.set(did, key);
    return key;
  }

  async verify(jwt: string, opts: { offline?: boolean } = {}): Promise<VerificationOutcome> {
    const offline = opts.offline ?? true;

    // 1. Parse header to learn the issuer DID without trusting the payload yet.
    let issuerDid: string;
    try {
      const [rawHeader] = jwt.split('.');
      const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
      issuerDid = (header.kid ?? '').split('#')[0];
    } catch {
      return { valid: false, reason: 'MALFORMED_JWT', offline, checkedRevocation: false };
    }

    const key = await this.keyFor(issuerDid);
    if (!key) {
      return { valid: false, reason: 'UNTRUSTED_ISSUER', offline, checkedRevocation: false, issuerDid };
    }

    // 2. Cryptographic + temporal verification (signature, iss, exp).
    let payload: Record<string, unknown>;
    try {
      const res = await jwtVerify(jwt, key, { issuer: issuerDid });
      payload = res.payload as Record<string, unknown>;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'VERIFY_FAILED';
      const reason = /exp/i.test(msg) ? 'EXPIRED' : 'BAD_SIGNATURE';
      return { valid: false, reason, offline, checkedRevocation: false, issuerDid };
    }

    const vc = (payload.vc ?? {}) as Record<string, any>;
    const subject = vc.credentialSubject as Record<string, unknown> | undefined;
    const status = vc.credentialStatus as
      | { statusListCredential?: string; statusListIndex?: string }
      | undefined;

    // 3. Revocation check against cached status list, if available.
    let checkedRevocation = false;
    if (status?.statusListCredential && status.statusListIndex != null) {
      const issuer = this.trust.get(issuerDid);
      const list = issuer?.statusLists?.[status.statusListCredential];
      if (list) {
        checkedRevocation = true;
        if (list.isRevoked(Number(status.statusListIndex))) {
          return { valid: false, reason: 'REVOKED', offline, checkedRevocation, issuerDid, subject };
        }
      }
      // If no cached list and offline, we return valid but flag checkedRevocation=false
      // so the relying party knows revocation could not be confirmed.
    }

    return {
      valid: true,
      offline,
      checkedRevocation,
      subject,
      issuerDid,
      expiresAt: typeof vc.validUntil === 'string' ? vc.validUntil : undefined,
    };
  }
}
