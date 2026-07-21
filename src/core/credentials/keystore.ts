import { generateKeyPair, exportJWK, importJWK, JWK, KeyLike } from 'jose';
import { LocalSigner, Signer } from './signer';

/**
 * Issuer signing key material.
 *
 * We use Ed25519 (EdDSA). Reasons that matter for a subnational DPG:
 *  - Signatures and public keys are tiny, which keeps credential QR codes scannable
 *    on cheap phones and printable on paper.
 *  - Verification needs only the public key and no network round-trip, which is the
 *    whole basis of offline verification in low-connectivity areas.
 *
 * In production the private key lives in an HSM/KMS and never touches disk. That is why
 * `privateKey` is optional here and `signer` is not: signing goes through the
 * `Signer` port, and a KMS-backed deployment has no exportable private key at all. Code
 * that reaches for `privateKey` is code that cannot run against an HSM -- the optional
 * type is what makes those places fail to compile rather than fail in production.
 */
export interface IssuerKey {
  kid: string;
  /**
   * Present only when key material is in-process: dev keys, or a JWK supplied via env.
   * Absent for HSM/KMS-backed signers. Prefer `signer` for anything that signs.
   */
  privateKey?: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
  signer: Signer;
}

export class KeyStore {
  static async fromJwk(privateJwk: JWK, kid: string): Promise<IssuerKey> {
    const privateKey = (await importJWK(privateJwk, 'EdDSA')) as KeyLike;
    const publicJwk: JWK = {
      kty: privateJwk.kty,
      crv: privateJwk.crv,
      x: privateJwk.x,
    };
    const publicKey = (await importJWK(publicJwk, 'EdDSA')) as KeyLike;
    const withKid = { ...publicJwk, kid };
    return {
      kid,
      privateKey,
      publicKey,
      publicJwk: withKid,
      signer: new LocalSigner(kid, withKid, privateKey),
    };
  }

  /**
   * Adopt an external signer (HSM, cloud KMS) as the issuer key. The private half never
   * enters this process, so only the public material is materialised here.
   */
  static async fromSigner(signer: Signer): Promise<IssuerKey> {
    const publicKey = (await importJWK(signer.publicJwk, 'EdDSA')) as KeyLike;
    return {
      kid: signer.kid,
      publicKey,
      publicJwk: signer.publicJwk,
      signer,
    };
  }

  /** Generate an ephemeral Ed25519 key. Dev/test only. */
  static async generate(kid = 'issuer-key-1'): Promise<IssuerKey> {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const publicJwk = { ...(await exportJWK(publicKey)), kid };
    return {
      kid,
      privateKey,
      publicKey,
      publicJwk,
      signer: new LocalSigner(kid, publicJwk, privateKey),
    };
  }
}
