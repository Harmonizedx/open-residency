import { jwtVerify, importJWK, errors, JWK, KeyLike } from 'jose';
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
  /**
   * Every public key this issuer has signed with, current first, retired ones after.
   *
   * A list rather than a single key because credentials outlive the key that signed
   * them. A residency credential is valid for years; a signing key is rotated far more
   * often than that. If the trust list only ever held the current key, the moment an
   * issuer rotated, every credential already in citizens' wallets would stop verifying
   * -- the signatures are still perfectly good, we would simply have thrown away the
   * public key needed to check them. Retiring a key means "stop signing with it", not
   * "invalidate everything it ever signed".
   */
  publicJwks: JWK[];
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

  /**
   * The cached status list for an issuer, if one has been synced.
   *
   * Exposed so the presentation verifier can check revocation for JSON-LD credentials
   * against the same snapshot the VC-JWT path uses. Keeping one cache rather than two is
   * what guarantees a revoked resident is revoked in both formats -- two caches would
   * eventually disagree, and a revoked credential would keep verifying in one of them.
   */
  statusListFor(issuerDid: string, statusListUrl: string): StatusList | undefined {
    return this.trust.get(issuerDid)?.statusLists?.[statusListUrl];
  }

  /**
   * The candidate keys for an issuer, most likely first.
   *
   * When the credential names a `kid` we try that key alone: it is the key the issuer
   * says signed, and trying the others afterwards would only turn a genuine mismatch
   * into a slower genuine mismatch. When there is no `kid` -- older credentials, and
   * other issuers' -- we fall back to trying every key we hold for that issuer.
   */
  private async keysFor(did: string, kid?: string): Promise<KeyLike[]> {
    const issuer = this.trust.get(did);
    if (!issuer) return [];
    const named = kid ? issuer.publicJwks.filter((j) => j.kid === kid) : [];
    const candidates = named.length ? named : issuer.publicJwks;

    const keys: KeyLike[] = [];
    for (const jwk of candidates) {
      const cacheKey = `${did}#${jwk.kid ?? ''}`;
      let key = this.keyCache.get(cacheKey);
      if (!key) {
        try {
          key = (await importJWK(jwk, 'EdDSA')) as KeyLike;
        } catch {
          continue; // a malformed entry in the trust list must not sink the good ones
        }
        this.keyCache.set(cacheKey, key);
      }
      keys.push(key);
    }
    return keys;
  }

  async verify(jwt: string, opts: { offline?: boolean } = {}): Promise<VerificationOutcome> {
    const offline = opts.offline ?? true;

    // 1. Parse header to learn the issuer DID without trusting the payload yet.
    let issuerDid: string;
    let signingKid: string | undefined;
    try {
      const [rawHeader] = jwt.split('.');
      const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
      const kid = String(header.kid ?? '');
      issuerDid = kid.split('#')[0];
      signingKid = kid.split('#')[1] || undefined;
    } catch {
      return { valid: false, reason: 'MALFORMED_JWT', offline, checkedRevocation: false };
    }

    const keys = await this.keysFor(issuerDid, signingKid);
    if (keys.length === 0) {
      return { valid: false, reason: 'UNTRUSTED_ISSUER', offline, checkedRevocation: false, issuerDid };
    }

    // 2. Cryptographic + temporal verification (signature, iss, exp), against each key
    // we hold for this issuer until one verifies.
    let payload: Record<string, unknown> | undefined;
    let failure = 'BAD_SIGNATURE';
    for (const key of keys) {
      try {
        const res = await jwtVerify(jwt, key, { issuer: issuerDid });
        payload = res.payload as Record<string, unknown>;
        break;
      } catch (e: unknown) {
        // Classify on jose's typed errors, NOT on the message text. Matching /exp/ against
        // the message looks reasonable and is quietly wrong: jose reports a bad claim as
        // `unexpected "iss" claim value`, and "unexpected" contains "exp" -- so a
        // wrong-issuer credential would be reported to the verifier as EXPIRED.
        //
        // Expiry and issuer claims are only checked once the signature has already
        // verified, so either of those reasons identifies the signing key and is final.
        // A bare signature failure just means "not this key" -- keep trying the rest.
        if (e instanceof errors.JWTExpired) {
          failure = 'EXPIRED';
          break;
        }
        if (e instanceof errors.JWTClaimValidationFailed) {
          failure = 'ISSUER_MISMATCH';
          break;
        }
      }
    }
    if (!payload) {
      return { valid: false, reason: failure, offline, checkedRevocation: false, issuerDid };
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
