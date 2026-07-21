import { sign as cryptoSign, KeyObject } from 'node:crypto';
import { base64url, JWK, KeyLike } from 'jose';

/**
 * The signing port.
 *
 * Everything this deployment signs -- credentials, access tokens, request objects,
 * consent receipts, operator sessions -- goes through `sign()`. The point of the
 * indirection is custody: a production issuer key belongs in an HSM or a cloud KMS and
 * must never be exported into this process. A remote signer cannot satisfy `jose`'s
 * `.sign(KeyLike)` API, because that API assumes local key material, so the codebase
 * signs bytes through this interface instead and assembles the JWS itself (below).
 *
 * The contract is deliberately the smallest thing every backend can honour:
 *
 *  - `sign()` takes the exact bytes to be signed and returns the signature in *JWS
 *    form*. For Ed25519 that is the raw 64-byte value, which is what both `node:crypto`
 *    and every KMS return, so no conversion is needed. An ECDSA backend would have to
 *    convert KMS's DER output to raw `r||s` here -- inside the adapter, never at the
 *    call sites.
 *
 *  - `publicJwk` is a plain property, not a fetch. Remote adapters resolve the public
 *    key once when they are constructed and cache it, because callers need it
 *    synchronously to build DID documents, JWKS responses, and verification methods.
 *
 * Adapters live alongside this file. `LocalSigner` is the in-process one (dev, and
 * env-supplied JWK); a KMS/HSM adapter implements the same three members and nothing
 * at any call site changes.
 */

/**
 * Issuance is Ed25519 throughout: `did.ts` rejects other multicodecs, the LD
 * cryptosuite is `eddsa-rdfc-2022`, and the OID4VCI metadata advertises EdDSA alone.
 * Adding ES256 is a cryptosuite project, not a signer swap -- so the port names the one
 * algorithm the stack actually issues rather than pretending to be generic.
 */
export type SignatureAlg = 'EdDSA';

export interface Signer {
  /** Key id published in JWKS and referenced by `kid` headers. */
  readonly kid: string;
  readonly alg: SignatureAlg;
  /** The public half, resolved once at construction. Carries `kid`. */
  readonly publicJwk: JWK;
  /** Sign exactly these bytes; return the signature in JWS form. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** In-process signer over local key material. Dev, tests, and env-supplied JWKs. */
export class LocalSigner implements Signer {
  readonly alg: SignatureAlg = 'EdDSA';

  constructor(
    readonly kid: string,
    readonly publicJwk: JWK,
    private readonly privateKey: KeyLike,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    // Ed25519 signs the message itself -- no pre-hash, and the algorithm argument must
    // be null. The result is the raw 64-byte signature JWS wants.
    return new Uint8Array(cryptoSign(null, data, this.privateKey as unknown as KeyObject));
  }
}

const utf8 = new TextEncoder();

export interface JwsHeader {
  typ?: string;
  kid?: string;
  [claim: string]: unknown;
}

export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  iat?: number;
  exp?: number;
  [claim: string]: unknown;
}

/**
 * Assemble and sign a compact JWS.
 *
 * `alg` is taken from the signer rather than the caller: the header has to describe the
 * key that actually signed, and a mismatch between the two is the kind of thing that
 * verifies in testing and fails in the field.
 */
export async function signCompactJws(
  signer: Signer,
  header: JwsHeader,
  payload: Record<string, unknown>,
): Promise<string> {
  const protectedHeader = base64url.encode(
    utf8.encode(JSON.stringify({ ...header, alg: signer.alg })),
  );
  const body = base64url.encode(utf8.encode(JSON.stringify(payload)));
  // Per RFC 7515 the signing input is the ASCII of "<header>.<payload>".
  const signingInput = `${protectedHeader}.${body}`;
  const signature = await signer.sign(utf8.encode(signingInput));
  return `${signingInput}.${base64url.encode(signature)}`;
}

/**
 * Sign a JWT. Registered claims are set explicitly by the caller; `iat` defaults to now
 * so every token this deployment issues carries one.
 */
export async function signJwt(
  signer: Signer,
  header: JwsHeader,
  claims: JwtClaims,
): Promise<string> {
  const iat = claims.iat ?? Math.floor(Date.now() / 1000);
  return signCompactJws(signer, { typ: 'JWT', ...header }, { ...claims, iat });
}