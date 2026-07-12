import { generateKeyPair, exportJWK, importJWK, JWK, KeyLike } from 'jose';

/**
 * Issuer signing key material.
 *
 * We use Ed25519 (EdDSA). Reasons that matter for a subnational DPG:
 *  - Signatures and public keys are tiny, which keeps credential QR codes scannable
 *    on cheap phones and printable on paper.
 *  - Verification needs only the public key and no network round-trip, which is the
 *    whole basis of offline verification in low-connectivity areas.
 *
 * In production the private key lives in an HSM/KMS and never touches disk. This
 * class supports loading an existing JWK (from KMS-exported material or a sealed
 * secret) or generating an ephemeral key for local dev.
 */
export interface IssuerKey {
  kid: string;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
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
    return { kid, privateKey, publicKey, publicJwk: { ...publicJwk, kid } };
  }

  /** Generate an ephemeral Ed25519 key. Dev/test only. */
  static async generate(kid = 'issuer-key-1'): Promise<IssuerKey> {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const publicJwk = await exportJWK(publicKey);
    return { kid, privateKey, publicKey, publicJwk: { ...publicJwk, kid } };
  }
}
