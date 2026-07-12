import { JWK } from 'jose';
import { base58btc } from './base58';

/**
 * Minimal DID support for issuer identity.
 *
 *  - did:web  is recommended for a government issuer (e.g. did:web:id.katsina.gov.ng).
 *    It is human-meaningful and lets the DID document be served from the state's own
 *    domain. Verifiers resolve it over HTTPS, then cache it for offline use.
 *
 *  - did:key  encodes the public key directly in the identifier. It needs no network
 *    at all to resolve, which makes it the strongest option for fully offline
 *    verification (a field officer's app can verify a credential having only the
 *    printed/loaded issuer key). We expose it for that inclusion scenario.
 */

// Multicodec prefix for Ed25519 public keys is 0xed 0x01.
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

function jwkToRawEd25519(jwk: JWK): Uint8Array {
  if (!jwk.x) throw new Error('JWK missing x (public key)');
  return new Uint8Array(Buffer.from(jwk.x, 'base64url'));
}

export function didKeyFromJwk(jwk: JWK): string {
  const raw = jwkToRawEd25519(jwk);
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + raw.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(raw, ED25519_MULTICODEC.length);
  return `did:key:${base58btc(prefixed)}`;
}

/** Build a W3C DID document for a did:web issuer, publishable at /.well-known/did.json */
export function buildDidWebDocument(did: string, publicJwk: JWK): Record<string, unknown> {
  const vmId = `${did}#${publicJwk.kid ?? 'key-1'}`;
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
      },
    ],
    assertionMethod: [vmId],
    authentication: [vmId],
  };
}

/** Convert a did:web string to the URL where its DID document is published. */
export function didWebToUrl(did: string): string {
  // did:web:id.katsina.gov.ng[:path] -> https://id.katsina.gov.ng[/path]/did.json
  const body = did.replace(/^did:web:/, '');
  const parts = body.split(':').map(decodeURIComponent);
  const host = parts.shift();
  const path = parts.length ? `/${parts.join('/')}` : '/.well-known';
  return `https://${host}${path}/did.json`;
}
