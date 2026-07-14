import { JWK, KeyLike, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { holderDidFromJwk, publicPartOf, resolveHolderDid } from '../credentials/did';

/**
 * Verification of the OpenID4VCI key proof (`typ: openid4vci-proof+jwt`).
 *
 * This is the step that turns a credential from a bearer token into something bound to
 * a person's device. The wallet signs a short-lived JWT with a key it holds; we check
 * that signature, then mint the credential with the corresponding DID as the subject.
 * From then on the credential is only usable by whoever holds that private key, because
 * presenting it (OpenID4VP) requires signing over a fresh verifier nonce.
 *
 * Spec: OpenID4VCI 1.0, Appendix F.1 (Key Proof Types).
 */

/**
 * Algorithms we accept from a wallet.
 *
 * RS256 is here because the Inji wallet hardcodes it in its proof generator. We would
 * not choose it, but refusing it means refusing the wallet this project most wants to
 * interoperate with. EdDSA and ES256 are the ones we recommend.
 */
export const SUPPORTED_PROOF_ALGS = ['EdDSA', 'ES256', 'RS256'] as const;

/** Wallet clocks drift. Allow a small window on `iat` rather than rejecting outright. */
const IAT_SKEW_SECONDS = 300;

export interface HolderProofResult {
  /** The public key the wallet proved possession of. */
  holderJwk: JWK;
  /** The DID we will use as `credentialSubject.id`. */
  holderDid: string;
  alg: string;
}

export class HolderProofError extends Error {
  /** Maps to the OpenID4VCI `invalid_proof` / `invalid_nonce` error codes. */
  constructor(
    message: string,
    public readonly code: 'invalid_proof' | 'invalid_nonce' = 'invalid_proof',
  ) {
    super(message);
    this.name = 'HolderProofError';
  }
}

export interface VerifyHolderProofOptions {
  /** Our Credential Issuer Identifier. The proof's `aud` must equal this. */
  credentialIssuer: string;
  /**
   * Consume the proof's nonce, returning false if it is unknown, expired, or already
   * used.
   *
   * This is a lookup rather than an equality check against one expected value, because
   * a wallet may legitimately sign over a c_nonce from either the token response
   * (Draft 13) or the Nonce Endpoint (1.0), and we do not know in advance which it
   * chose. The store decides, and it is the store that enforces single use.
   *
   * Only called after the signature has already verified, so a garbage proof cannot
   * burn a valid nonce.
   */
  consumeNonce: (nonce: string) => Promise<boolean>;
}

/**
 * Recover the wallet's public key from the proof header.
 *
 * Exactly one of `jwk`, `kid`, or `x5c` is permitted by the spec. We support the first
 * two: `jwk` (the key inline, which is what Inji sends) and `kid` (a DID URL we can
 * resolve offline). We do not support `x5c`, because accepting an X.509 chain would
 * mean taking on a PKI trust decision that this issuer has no basis to make.
 */
function keyFromHeader(header: Record<string, unknown>): JWK {
  const declared = ['jwk', 'kid', 'x5c'].filter((k) => header[k] != null);
  if (declared.length !== 1) {
    throw new HolderProofError(
      `proof header must carry exactly one of jwk, kid, or x5c (found: ${
        declared.length ? declared.join(', ') : 'none'
      })`,
    );
  }

  if (header.jwk) {
    const jwk = header.jwk as JWK;
    // A wallet must never send us private key material. If it does, something is very
    // wrong on its side; refuse rather than quietly using the public half.
    if (jwk.d != null) {
      throw new HolderProofError('proof header jwk contains private key material');
    }
    return publicPartOf(jwk);
  }

  if (header.x5c) {
    throw new HolderProofError('x5c key proofs are not supported by this issuer');
  }

  const kid = String(header.kid);
  try {
    return resolveHolderDid(kid);
  } catch (e) {
    throw new HolderProofError(
      `could not resolve proof kid '${kid}': ${e instanceof Error ? e.message : 'unknown'}`,
    );
  }
}

/**
 * Verify a wallet's key proof and return the key it is bound to.
 *
 * Note on `iss`: the spec says it MUST be omitted in the pre-authorized (anonymous)
 * flow, but Inji sends it anyway. Rejecting on that basis would break the wallet for
 * no security benefit, since `iss` is not a claim we rely on. We ignore it. Likewise
 * Inji adds a non-standard `exp`; we honour it if present but do not require it.
 */
export async function verifyHolderProof(
  proofJwt: string,
  opts: VerifyHolderProofOptions,
): Promise<HolderProofResult> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(proofJwt) as Record<string, unknown>;
  } catch {
    throw new HolderProofError('proof is not a well-formed JWT');
  }

  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new HolderProofError(
      `proof header typ must be 'openid4vci-proof+jwt' (got '${String(header.typ)}')`,
    );
  }

  const alg = String(header.alg ?? '');
  if (!(SUPPORTED_PROOF_ALGS as readonly string[]).includes(alg)) {
    throw new HolderProofError(
      `unsupported proof alg '${alg}'; expected one of ${SUPPORTED_PROOF_ALGS.join(', ')}`,
    );
  }

  const holderJwk = keyFromHeader(header);

  let key: KeyLike;
  try {
    key = (await importJWK(holderJwk, alg)) as KeyLike;
  } catch {
    throw new HolderProofError('proof key is not a usable public key');
  }

  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(proofJwt, key, {
      audience: opts.credentialIssuer,
      // `iss` is deliberately not constrained: see the note above.
      clockTolerance: IAT_SKEW_SECONDS,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'verification failed';
    if (/audience/i.test(msg)) {
      throw new HolderProofError(
        `proof aud does not match this credential issuer (${opts.credentialIssuer})`,
      );
    }
    if (/exp/i.test(msg)) throw new HolderProofError('proof has expired');
    throw new HolderProofError('proof signature does not verify');
  }

  // `iat` is REQUIRED. Enforce freshness so a proof captured from one issuance cannot
  // be replayed indefinitely, independently of the nonce check below.
  const iat = payload.iat;
  if (typeof iat !== 'number') {
    throw new HolderProofError('proof is missing the required iat claim');
  }
  const ageSeconds = Math.floor(Date.now() / 1000) - iat;
  if (ageSeconds > IAT_SKEW_SECONDS || ageSeconds < -IAT_SKEW_SECONDS) {
    throw new HolderProofError(`proof iat is outside the accepted window (${ageSeconds}s off)`);
  }

  // The nonce is what actually stops replay: we minted it, and it is good exactly once.
  const nonce = payload.nonce;
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new HolderProofError('proof is missing the required nonce claim', 'invalid_nonce');
  }
  if (!(await opts.consumeNonce(nonce))) {
    throw new HolderProofError(
      'proof nonce is unknown, expired, or has already been used',
      'invalid_nonce',
    );
  }

  return { holderJwk, holderDid: holderDidFromJwk(holderJwk), alg };
}
