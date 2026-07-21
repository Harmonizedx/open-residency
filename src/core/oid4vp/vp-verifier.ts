import { JWK, KeyLike, decodeProtectedHeader, errors, importJWK, jwtVerify } from 'jose';
import { createPublicKey, KeyObject } from 'node:crypto';
import { resolveHolderDid } from '../credentials/did';
import { LdpIssuer, LdpCredential } from '../credentials/ldp-issuer';
import { VcVerifier } from '../credentials/vc-verifier';

/**
 * Verification of a Verifiable Presentation.
 *
 * The distinction between verifying a *credential* and verifying a *presentation* is the
 * whole reason this file exists, and it is worth being precise about.
 *
 * The existing `POST /residency/verify` takes a raw VC-JWT and checks that the issuer
 * signed it, that it has not expired, and that it is not revoked. Every one of those
 * checks passes for a credential that was copied from somebody else. It answers "is this
 * a genuine credential?" -- not "is the person in front of me its holder?", and not "was
 * this presented to ME, just now?".
 *
 * A presentation answers those. The holder signs a fresh object, over a nonce the
 * verifier chose, naming the verifier as the audience. So this verifier enforces four
 * things beyond credential validity:
 *
 *   1. HOLDER BINDING  -- the presentation is signed by the key named in the credential's
 *      `credentialSubject.id`. Presenting a credential you do not hold the key for fails.
 *   2. FRESHNESS       -- the nonce is one we just issued, and it is single-use. A
 *      captured presentation cannot be replayed at us again.
 *   3. AUDIENCE        -- `aud` is us. A presentation captured by a shop cannot be
 *      replayed by that shop at a hospital.
 *   4. The enclosed credential is itself valid (signature, expiry, revocation), which is
 *      delegated to the existing VcVerifier / LdpIssuer.verify.
 *
 * Drop any one of the first three and the credential collapses back into a bearer token.
 */

export interface VpVerificationOptions {
  /** The nonce we issued for this request. */
  expectedNonce: string;
  /** Our client_id. The presentation's `aud` must be this. */
  expectedAudience: string;
}

export interface VpVerificationOutcome {
  valid: boolean;
  reason?: string;
  /** The DID that signed the presentation. */
  holderDid?: string;
  /** Claims from the credential inside, once everything checks out. */
  subject?: Record<string, unknown>;
  issuerDid?: string;
  checkedRevocation: boolean;
}

/** Public keys of issuers we trust, by DID, for verifying the credential inside. */
export interface VpTrustedIssuer {
  did: string;
  /** Current key first, then retired ones, so credentials survive a rotation. */
  publicKeyObjects: KeyObject[];
}

export class VpVerifier {
  constructor(
    /** Verifies the enclosed VC-JWT (signature, expiry, revocation, status list). */
    private vcVerifier: VcVerifier,
    /** Issuer keys, for verifying an enclosed JSON-LD credential's Data Integrity proof. */
    private ldpTrust: Map<string, VpTrustedIssuer>,
  ) {}

  async verify(vpToken: string, opts: VpVerificationOptions): Promise<VpVerificationOutcome> {
    // ---- 1. Who signed the presentation? -----------------------------------
    // Read the holder DID from the header, but trust nothing yet.
    let holderDid: string;
    let alg: string;
    try {
      const header = decodeProtectedHeader(vpToken) as Record<string, unknown>;
      alg = String(header.alg ?? '');
      const kid = String(header.kid ?? '');
      holderDid = kid.split('#')[0];
      if (!holderDid) throw new Error('no kid');
    } catch {
      return { valid: false, reason: 'MALFORMED_VP', checkedRevocation: false };
    }

    let holderKey: KeyLike;
    try {
      holderKey = (await importJWK(resolveHolderDid(holderDid), alg)) as KeyLike;
    } catch {
      return { valid: false, reason: 'UNRESOLVABLE_HOLDER_DID', checkedRevocation: false, holderDid };
    }

    // ---- 2. Holder signature, audience, and expiry --------------------------
    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(vpToken, holderKey, {
        audience: opts.expectedAudience,
        clockTolerance: 120,
      });
      payload = verified.payload as Record<string, unknown>;
    } catch (e) {
      // Classify on jose's typed errors, never on the message text. jose words an
      // audience mismatch as `unexpected "aud" claim value` -- and "unexpected" contains
      // the substring "exp", so a naive /exp/ test reports a cross-verifier replay as a
      // merely expired presentation. That is the difference between "your card timed out"
      // and "someone is replaying your card at a second verifier".
      const reason =
        e instanceof errors.JWTExpired
          ? 'EXPIRED_PRESENTATION'
          : e instanceof errors.JWTClaimValidationFailed && e.claim === 'aud'
            ? 'WRONG_AUDIENCE'
            : 'BAD_HOLDER_SIGNATURE';
      return { valid: false, reason, checkedRevocation: false, holderDid };
    }

    // ---- 3. Freshness -------------------------------------------------------
    if (payload.nonce !== opts.expectedNonce) {
      return { valid: false, reason: 'NONCE_MISMATCH', checkedRevocation: false, holderDid };
    }

    // ---- 4. The credential inside -------------------------------------------
    const vp = (payload.vp ?? {}) as Record<string, unknown>;
    const credentials = vp.verifiableCredential;
    const list = Array.isArray(credentials) ? credentials : credentials ? [credentials] : [];
    if (list.length === 0) {
      return { valid: false, reason: 'NO_CREDENTIAL_PRESENTED', checkedRevocation: false, holderDid };
    }

    // We only ever ask for one residency credential, so verify the first and ignore the
    // rest rather than silently accepting a bundle we did not request.
    const presented = list[0];

    const result =
      typeof presented === 'string'
        ? await this.verifyJwtCredential(presented)
        : await this.verifyLdpCredential(presented as LdpCredential);

    if (!result.valid) return { ...result, holderDid };

    // ---- 5. Holder binding: the crux ----------------------------------------
    // The credential must have been issued TO the key that just signed this
    // presentation. Without this check, anyone who obtained a copy of somebody's
    // credential could present it under their own key and be believed.
    const subjectId = result.subject?.id;
    if (subjectId !== holderDid) {
      return {
        valid: false,
        reason: 'HOLDER_NOT_SUBJECT',
        checkedRevocation: result.checkedRevocation,
        holderDid,
        issuerDid: result.issuerDid,
      };
    }

    // ---- 6. Fail closed if revocation could not be checked -------------------
    //
    // The credential verifier is deliberately permissive here: a field officer with no
    // connectivity should still be able to check a card against whatever status snapshot
    // they last synced, and it reports `checkedRevocation: false` so they know what they
    // are getting.
    //
    // An online presentation is a different situation entirely. This code path runs on a
    // server that just synced the status list; if we have no list to check against,
    // something is wrong -- and "accept it anyway, but set a flag" means a revoked
    // credential is accepted by any relying party that does not read the flag. Nobody
    // reads the flag. So the presentation path fails closed.
    if (!result.checkedRevocation) {
      return {
        valid: false,
        reason: 'REVOCATION_UNCHECKABLE',
        checkedRevocation: false,
        holderDid,
        issuerDid: result.issuerDid,
      };
    }

    return { ...result, holderDid };
  }

  /** Verify an enclosed VC-JWT via the existing verifier (signature, expiry, revocation). */
  private async verifyJwtCredential(jwt: string): Promise<VpVerificationOutcome> {
    const outcome = await this.vcVerifier.verify(jwt, { offline: true });
    return {
      valid: outcome.valid,
      reason: outcome.reason,
      subject: outcome.subject,
      issuerDid: outcome.issuerDid,
      checkedRevocation: outcome.checkedRevocation,
    };
  }

  /**
   * Verify an enclosed JSON-LD credential: Data Integrity proof, expiry, and revocation.
   *
   * Revocation is checked against the same cached status list the VC-JWT path uses, so a
   * revoked resident is revoked regardless of which format their wallet holds.
   */
  private async verifyLdpCredential(credential: LdpCredential): Promise<VpVerificationOutcome> {
    const issuerField = credential.issuer as { id?: string } | string | undefined;
    const issuerDid = typeof issuerField === 'string' ? issuerField : issuerField?.id;
    if (!issuerDid) {
      return { valid: false, reason: 'NO_ISSUER', checkedRevocation: false };
    }

    const trusted = this.ldpTrust.get(issuerDid);
    if (!trusted) {
      return { valid: false, reason: 'UNTRUSTED_ISSUER', checkedRevocation: false, issuerDid };
    }

    if (!(await LdpIssuer.verify(credential, trusted.publicKeyObjects))) {
      return { valid: false, reason: 'BAD_SIGNATURE', checkedRevocation: false, issuerDid };
    }

    const validUntil = credential.validUntil;
    if (typeof validUntil === 'string' && new Date(validUntil).getTime() < Date.now()) {
      return { valid: false, reason: 'EXPIRED', checkedRevocation: false, issuerDid };
    }

    const subject = credential.credentialSubject as Record<string, unknown> | undefined;
    const status = credential.credentialStatus as
      | { statusListCredential?: string; statusListIndex?: string }
      | undefined;

    let checkedRevocation = false;
    if (status?.statusListCredential && status.statusListIndex != null) {
      const list = this.vcVerifier.statusListFor(issuerDid, status.statusListCredential);
      if (list) {
        checkedRevocation = true;
        if (list.isRevoked(Number(status.statusListIndex))) {
          return { valid: false, reason: 'REVOKED', checkedRevocation, issuerDid, subject };
        }
      }
    }

    return { valid: true, subject, issuerDid, checkedRevocation };
  }
}

/** Build a Node KeyObject from a JWK, for Data Integrity verification. */
export function keyObjectFromJwk(jwk: JWK): KeyObject {
  return createPublicKey({ key: jwk as any, format: 'jwk' });
}
