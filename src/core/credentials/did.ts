import { JWK } from 'jose';
import { base58btc, base58btcDecode } from './base58';

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
  return `did:key:${ed25519Multikey(jwk)}`;
}

/**
 * The multibase form of an Ed25519 public key (z6Mk...), used both as the body of a
 * did:key and as `publicKeyMultibase` in a Multikey verification method.
 */
export function ed25519Multikey(jwk: JWK): string {
  const raw = jwkToRawEd25519(jwk);
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + raw.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(raw, ED25519_MULTICODEC.length);
  return base58btc(prefixed);
}

/** Resolve a did:key back to its public JWK. Ed25519 only; no network access. */
export function didKeyToJwk(did: string): JWK {
  const body = did.replace(/^did:key:/, '').split('#')[0];
  const decoded = base58btcDecode(body);
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error('unsupported did:key multicodec (only Ed25519 is supported)');
  }
  const raw = decoded.slice(ED25519_MULTICODEC.length);
  if (raw.length !== 32) throw new Error('invalid Ed25519 key length in did:key');
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') };
}

/** did:jwk — the public key encoded directly in the identifier. Any key type. */
export function didJwkFromJwk(jwk: JWK): string {
  const pub = publicPartOf(jwk);
  return `did:jwk:${Buffer.from(JSON.stringify(pub)).toString('base64url')}`;
}

export function didJwkToJwk(did: string): JWK {
  const body = did.replace(/^did:jwk:/, '').split('#')[0];
  return JSON.parse(Buffer.from(body, 'base64url').toString()) as JWK;
}

/** Strip any private material, so we never echo a `d` back into a DID or DID document. */
export function publicPartOf(jwk: JWK): JWK {
  const { kty, crv, x, y, n, e } = jwk;
  const pub: JWK = { kty };
  if (crv) pub.crv = crv;
  if (x) pub.x = x;
  if (y) pub.y = y;
  if (n) pub.n = n;
  if (e) pub.e = e;
  return pub;
}

/**
 * Choose the DID form for a credential holder, given the key they proved possession of.
 *
 * Ed25519 gets a did:key: it is the shortest identifier, keeps the credential QR
 * scannable, and needs no network to resolve. Anything else (P-256, and the RSA keys
 * that the Inji wallet actually sends) gets a did:jwk, which carries the key inline
 * and is likewise offline-resolvable. Both choices preserve the property that matters
 * most here: a field verifier with no connectivity can still resolve the holder's key.
 */
export function holderDidFromJwk(jwk: JWK): string {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return didKeyFromJwk(jwk);
  return didJwkFromJwk(jwk);
}

/** Resolve a holder DID (did:key or did:jwk) back to a public JWK, offline. */
export function resolveHolderDid(did: string): JWK {
  if (did.startsWith('did:key:')) return didKeyToJwk(did);
  if (did.startsWith('did:jwk:')) return didJwkToJwk(did);
  throw new Error(`unsupported holder DID method: ${did.split(':').slice(0, 2).join(':')}`);
}

/**
 * Build a W3C DID document for a did:web issuer, publishable at /.well-known/did.json
 *
 * Two verification methods are published for the same key:
 *   - JsonWebKey2020, which VC-JWT verifiers resolve, and
 *   - Multikey, which the `eddsa-rdfc-2022` Data Integrity cryptosuite requires.
 * We issue in both formats (jwt_vc_json and ldp_vc), so both must resolve.
 */
export function buildDidWebDocument(did: string, publicJwk: JWK): Record<string, unknown> {
  const kid = publicJwk.kid ?? 'key-1';
  const jwkVmId = `${did}#${kid}`;
  const multikeyVmId = `${did}#${ed25519Multikey(publicJwk)}`;
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
      'https://w3id.org/security/multikey/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: jwkVmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicPartOf(publicJwk),
      },
      {
        id: multikeyVmId,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: ed25519Multikey(publicJwk),
      },
    ],
    assertionMethod: [jwkVmId, multikeyVmId],
    authentication: [jwkVmId, multikeyVmId],
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
