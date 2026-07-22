import {
  createHash,
  createPublicKey,
  createVerify,
  verify as edVerify,
  KeyObject,
  type JsonWebKey,
} from 'node:crypto';
import { JWK } from 'jose';

/**
 * WebAuthn (FIDO2) as a phishing-resistant sign-in factor for the residency IdP.
 *
 * This is the server half of the two ceremonies -- registration (bind a passkey to a
 * resident) and authentication (prove possession of that passkey at sign-in). It is the
 * security-critical part, so it is implemented directly against the spec rather than
 * hidden in a dependency: every check a relying party MUST perform is here and named.
 *
 * Why WebAuthn is worth its own factor rather than another OTP: the authenticator signs
 * over an origin the browser fills in, and the server checks that origin. A one-time code
 * can be phished onto an attacker's site by a citizen who was tricked into typing it; a
 * passkey assertion made against the wrong origin simply does not verify. That is the
 * difference that lets WebAuthn raise the assurance level (see assurance.ts), not just add
 * a second prompt.
 *
 * Scope: the ceremonies and their verification. Credential storage and the HTTP endpoints
 * are the integration layer on top (a WebAuthnCredentialStore port); nothing here touches
 * a database or a framework, which is what lets it be tested end to end against a
 * simulated authenticator.
 */

// --------------------------------------------------------------------------
// Minimal CBOR decode -- only the subset a COSE key and attested credential
// data use (maps, arrays, unsigned/negative ints, byte/text strings). A full
// CBOR library is a large dependency for parsing one small, fixed-shape map.
// --------------------------------------------------------------------------

interface CborResult {
  value: unknown;
  offset: number;
}

function decodeCbor(buf: Buffer, offset: number): CborResult {
  const first = buf[offset];
  const major = first >> 5;
  const info = first & 0x1f;
  let len = info;
  let cursor = offset + 1;
  if (info === 24) {
    len = buf[cursor];
    cursor += 1;
  } else if (info === 25) {
    len = buf.readUInt16BE(cursor);
    cursor += 2;
  } else if (info === 26) {
    len = buf.readUInt32BE(cursor);
    cursor += 4;
  } else if (info > 26) {
    throw new Error(`unsupported CBOR additional-info ${info}`);
  }

  switch (major) {
    case 0: // unsigned int
      return { value: len, offset: cursor };
    case 1: // negative int
      return { value: -1 - len, offset: cursor };
    case 2: // byte string
      return { value: buf.subarray(cursor, cursor + len), offset: cursor + len };
    case 3: // text string
      return { value: buf.subarray(cursor, cursor + len).toString('utf8'), offset: cursor + len };
    case 4: {
      // array
      const arr: unknown[] = [];
      let c = cursor;
      for (let i = 0; i < len; i++) {
        const r = decodeCbor(buf, c);
        arr.push(r.value);
        c = r.offset;
      }
      return { value: arr, offset: c };
    }
    case 5: {
      // map
      const map = new Map<unknown, unknown>();
      let c = cursor;
      for (let i = 0; i < len; i++) {
        const k = decodeCbor(buf, c);
        const v = decodeCbor(buf, k.offset);
        map.set(k.value, v.value);
        c = v.offset;
      }
      return { value: map, offset: c };
    }
    default:
      throw new Error(`unsupported CBOR major type ${major}`);
  }
}

const b64url = (b: Buffer | Uint8Array): string => Buffer.from(b).toString('base64url');

/** COSE signature algorithms this deployment accepts, and their JWS/JOSE equivalents. */
export type WebAuthnAlg = 'ES256' | 'EdDSA' | 'RS256';
const COSE_ALG: Record<number, WebAuthnAlg> = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };

/**
 * Convert a COSE_Key (the public key an authenticator emits) to a JWK.
 *
 * Only the curve/key types WebAuthn authenticators actually produce: EC2/P-256 (ES256),
 * OKP/Ed25519 (EdDSA), and RSA (RS256). An unknown one is refused rather than guessed.
 */
export function coseKeyToJwk(coseBytes: Buffer): { jwk: JWK; alg: WebAuthnAlg } {
  const { value } = decodeCbor(coseBytes, 0);
  const m = value as Map<number, unknown>;
  const kty = m.get(1) as number;
  const alg = COSE_ALG[m.get(3) as number];
  if (!alg) throw new Error(`unsupported COSE alg ${m.get(3)}`);

  if (kty === 2) {
    // EC2 (P-256 for ES256). x = -2, y = -3.
    return {
      jwk: { kty: 'EC', crv: 'P-256', x: b64url(m.get(-2) as Buffer), y: b64url(m.get(-3) as Buffer) },
      alg,
    };
  }
  if (kty === 1) {
    // OKP (Ed25519 for EdDSA). x = -2.
    return { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(m.get(-2) as Buffer) }, alg };
  }
  if (kty === 3) {
    // RSA. n = -1, e = -2.
    return { jwk: { kty: 'RSA', n: b64url(m.get(-1) as Buffer), e: b64url(m.get(-2) as Buffer) }, alg };
  }
  throw new Error(`unsupported COSE key type ${kty}`);
}

export interface AuthenticatorData {
  rpIdHash: Buffer;
  /** User Present. */
  up: boolean;
  /** User Verified (a PIN/biometric was checked on the device). */
  uv: boolean;
  /** Attested credential data present (registration). */
  at: boolean;
  signCount: number;
  /** Present on registration: the new credential's id and public key. */
  credentialId?: Buffer;
  credentialPublicKey?: Buffer;
}

/** Parse the fixed-layout authenticatorData byte string. */
export function parseAuthenticatorData(data: Buffer): AuthenticatorData {
  if (data.length < 37) throw new Error('authenticatorData too short');
  const rpIdHash = data.subarray(0, 32);
  const flags = data[32];
  const signCount = data.readUInt32BE(33);
  const at = (flags & 0x40) !== 0;

  const out: AuthenticatorData = {
    rpIdHash,
    up: (flags & 0x01) !== 0,
    uv: (flags & 0x04) !== 0,
    at,
    signCount,
  };

  if (at) {
    // attestedCredentialData: aaguid(16) + credIdLen(2) + credId + COSEKey(CBOR)
    let cursor = 37 + 16;
    const credIdLen = data.readUInt16BE(cursor);
    cursor += 2;
    out.credentialId = data.subarray(cursor, cursor + credIdLen);
    cursor += credIdLen;
    out.credentialPublicKey = data.subarray(cursor);
  }
  return out;
}

export interface RegisteredCredential {
  credentialId: string; // base64url
  publicJwk: JWK;
  alg: WebAuthnAlg;
  signCount: number;
}

export interface RegistrationCeremony {
  /** base64url authenticatorData from the attestationObject. */
  authData: string;
  /** base64url clientDataJSON. */
  clientDataJSON: string;
}

export interface AuthenticationCeremony {
  credentialId: string; // base64url
  authenticatorData: string; // base64url
  clientDataJSON: string; // base64url
  signature: string; // base64url
}

export interface CeremonyExpectations {
  challenge: string; // the base64url challenge the server issued
  origin: string; // e.g. https://id.katsina.gov.ng
  rpId: string; // e.g. id.katsina.gov.ng
  /** Require the authenticator to have verified the user (PIN/biometric) on-device. */
  requireUserVerification?: boolean;
}

function checkClientData(clientDataJSON: Buffer, type: string, exp: CeremonyExpectations): void {
  const cd = JSON.parse(clientDataJSON.toString('utf8')) as { type: string; challenge: string; origin: string };
  if (cd.type !== type) throw new Error(`clientData.type is "${cd.type}", expected "${type}"`);
  // The challenge the authenticator signed must be the exact one we issued -- this is what
  // stops a captured assertion being replayed with a stale challenge.
  if (cd.challenge !== exp.challenge) throw new Error('clientData.challenge does not match the issued challenge');
  // The origin the browser reported must be ours. This is the phishing-resistance check:
  // an assertion made on an attacker's page carries the attacker's origin and fails here.
  if (cd.origin !== exp.origin) throw new Error(`clientData.origin is "${cd.origin}", expected "${exp.origin}"`);
}

function checkAuthData(auth: AuthenticatorData, exp: CeremonyExpectations): void {
  const expectedRpIdHash = createHash('sha256').update(exp.rpId, 'utf8').digest();
  if (!auth.rpIdHash.equals(expectedRpIdHash)) throw new Error('rpIdHash does not match the expected rpId');
  if (!auth.up) throw new Error('user-present flag is not set');
  if (exp.requireUserVerification && !auth.uv) throw new Error('user verification was required but not performed');
}

/**
 * Registration: verify the attestation ceremony and extract the credential to store.
 *
 * Attestation-statement verification (proving which authenticator MODEL signed) is
 * deliberately not enforced here: for a citizen sign-in factor the relevant properties
 * are possession and user verification, not the make of the device, and requiring
 * attestation locks out perfectly good authenticators. The public key and the UV signal
 * are what get bound to the resident.
 */
export function verifyRegistration(
  ceremony: RegistrationCeremony,
  exp: CeremonyExpectations,
): RegisteredCredential {
  checkClientData(Buffer.from(ceremony.clientDataJSON, 'base64url'), 'webauthn.create', exp);
  const auth = parseAuthenticatorData(Buffer.from(ceremony.authData, 'base64url'));
  checkAuthData(auth, exp);
  if (!auth.at || !auth.credentialId || !auth.credentialPublicKey) {
    throw new Error('registration ceremony carried no attested credential data');
  }
  const { jwk, alg } = coseKeyToJwk(auth.credentialPublicKey);
  return { credentialId: b64url(auth.credentialId), publicJwk: jwk, alg, signCount: auth.signCount };
}

export interface AssertionResult {
  ok: boolean;
  reason?: string;
  /** The authenticator's new signature counter, to persist for clone detection. */
  newSignCount?: number;
}

/**
 * Authentication: verify a passkey assertion against a previously registered credential.
 *
 * The signature is over authenticatorData || SHA-256(clientDataJSON), per the spec. Every
 * failure is a clean `ok: false`, never a throw, because this runs on attacker-supplied
 * input during sign-in and must not turn a bad assertion into a 500.
 */
export function verifyAssertion(
  ceremony: AuthenticationCeremony,
  credential: RegisteredCredential,
  exp: CeremonyExpectations,
): AssertionResult {
  try {
    if (ceremony.credentialId !== credential.credentialId) {
      return { ok: false, reason: 'CREDENTIAL_MISMATCH' };
    }
    const clientDataJSON = Buffer.from(ceremony.clientDataJSON, 'base64url');
    checkClientData(clientDataJSON, 'webauthn.get', exp);

    const authDataBytes = Buffer.from(ceremony.authenticatorData, 'base64url');
    const auth = parseAuthenticatorData(authDataBytes);
    checkAuthData(auth, exp);

    // Clone detection: a counter that goes backwards means two copies of the key exist.
    // (A steady 0/0 is allowed -- some authenticators do not implement the counter.)
    if (credential.signCount !== 0 && auth.signCount !== 0 && auth.signCount <= credential.signCount) {
      return { ok: false, reason: 'SIGN_COUNT_REGRESSION' };
    }

    const signed = Buffer.concat([authDataBytes, createHash('sha256').update(clientDataJSON).digest()]);
    const signature = Buffer.from(ceremony.signature, 'base64url');
    if (!verifySignature(credential, signed, signature)) {
      return { ok: false, reason: 'BAD_SIGNATURE' };
    }
    return { ok: true, newSignCount: auth.signCount };
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
}

function verifySignature(credential: RegisteredCredential, signed: Buffer, signature: Buffer): boolean {
  const key: KeyObject = createPublicKey({ key: credential.publicJwk as JsonWebKey, format: 'jwk' });
  if (credential.alg === 'EdDSA') {
    return edVerify(null, signed, key, signature);
  }
  // ES256 (ECDSA/SHA-256, DER signature) and RS256 (RSASSA-PKCS1v1.5/SHA-256).
  const v = createVerify('SHA256');
  v.update(signed);
  v.end();
  return v.verify(key, signature);
}