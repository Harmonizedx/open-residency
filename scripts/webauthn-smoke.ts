/* eslint-disable no-console */
/**
 * WebAuthn step-up factor + assurance model, exercised against a SIMULATED authenticator.
 *
 * There is no browser and no hardware key here, exactly as the OpenID4VP suite has no real
 * wallet: the test constructs the precise wire artifacts a real authenticator produces --
 * a COSE public key, an authenticatorData byte string, a clientDataJSON, and a signature
 * over `authData || SHA256(clientData)` -- for both an Ed25519 and a P-256 authenticator,
 * and drives the real server-side registration and authentication verification. That
 * proves the security logic (origin binding, challenge binding, signature, clone counter)
 * without simulating away the part under test.
 *
 * It also proves the assurance model: which factor combinations yield which acr/amr, and
 * that an attested biometric match (via the pluggable port's mock) is what lifts WebAuthn
 * to the highest level.
 */
import {
  generateKeyPairSync,
  sign as edSign,
  createSign,
  createHash,
  randomBytes,
  KeyObject,
} from 'node:crypto';
import {
  verifyRegistration,
  verifyAssertion,
  coseKeyToJwk,
  parseAuthenticatorData,
  RegisteredCredential,
  CeremonyExpectations,
} from '../src/core/sso/webauthn';
import { assess, meetsRequirement } from '../src/core/sso/assurance';
import { MockBiometricMatcher } from '../src/core/proofing/biometric';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
}

const RP_ID = 'id.katsina.gov.ng';
const ORIGIN = 'https://id.katsina.gov.ng';
const b64url = (b: Buffer): string => b.toString('base64url');

// --- Minimal CBOR encoder, only what a COSE key needs (small int-keyed maps) ---
function cborUint(n: number): Buffer {
  if (n < 24) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x18, n]);
  return Buffer.from([0x19, n >> 8, n & 0xff]);
}
function cborInt(n: number): Buffer {
  if (n >= 0) return cborUint(n);
  const m = -1 - n;
  const u = cborUint(m);
  u[0] |= 0x20; // major type 1 (negative)
  return u;
}
function cborBytes(b: Buffer): Buffer {
  const head = cborUint(b.length);
  head[0] |= 0x40; // major type 2 (byte string)
  return Buffer.concat([head, b]);
}
function cborMap(pairs: [number, Buffer][]): Buffer {
  const head = cborUint(pairs.length);
  head[0] |= 0xa0; // major type 5 (map)
  return Buffer.concat([head, ...pairs.map(([k, v]) => Buffer.concat([cborInt(k), v]))]);
}

/** A simulated authenticator: an on-device key plus the ceremonies it produces. */
interface SimAuthenticator {
  alg: 'EdDSA' | 'ES256';
  key: KeyObject;
  coseKey: Buffer;
  credentialId: Buffer;
  sign(data: Buffer): Buffer;
}

function makeEd25519Authenticator(): SimAuthenticator {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const coseKey = cborMap([
    [1, cborInt(1)], // kty: OKP
    [3, cborInt(-8)], // alg: EdDSA
    [-1, cborInt(6)], // crv: Ed25519
    [-2, cborBytes(x)], // x
  ]);
  return {
    alg: 'EdDSA',
    key: privateKey,
    coseKey,
    credentialId: randomBytes(16),
    sign: (data) => edSign(null, data, privateKey),
  };
}

function makeP256Authenticator(): SimAuthenticator {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const coseKey = cborMap([
    [1, cborInt(2)], // kty: EC2
    [3, cborInt(-7)], // alg: ES256
    [-1, cborInt(1)], // crv: P-256
    [-2, cborBytes(Buffer.from(jwk.x, 'base64url'))],
    [-3, cborBytes(Buffer.from(jwk.y, 'base64url'))],
  ]);
  return {
    alg: 'ES256',
    key: privateKey,
    coseKey,
    credentialId: randomBytes(16),
    sign: (data) => {
      const s = createSign('SHA256');
      s.update(data);
      s.end();
      return s.sign(privateKey); // DER, as WebAuthn requires for ES256
    },
  };
}

function rpIdHash(): Buffer {
  return createHash('sha256').update(RP_ID, 'utf8').digest();
}

/** Build authenticatorData: rpIdHash(32) + flags(1) + signCount(4) [+ attestedCredentialData]. */
function authData(flags: number, signCount: number, attested?: SimAuthenticator): Buffer {
  const head = Buffer.concat([rpIdHash(), Buffer.from([flags]), Buffer.alloc(4)]);
  head.writeUInt32BE(signCount, 33);
  if (!attested) return head;
  const aaguid = Buffer.alloc(16);
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(attested.credentialId.length, 0);
  return Buffer.concat([head, aaguid, idLen, attested.credentialId, attested.coseKey]);
}

function clientData(type: string, challenge: string, origin = ORIGIN): Buffer {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8');
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

function registerAuthenticator(sim: SimAuthenticator, challenge: string): RegisteredCredential {
  const ad = authData(FLAG_UP | FLAG_UV | FLAG_AT, 0, sim);
  const cd = clientData('webauthn.create', challenge);
  return verifyRegistration(
    { authData: b64url(ad), clientDataJSON: b64url(cd) },
    { challenge, origin: ORIGIN, rpId: RP_ID, requireUserVerification: true },
  );
}

/** Produce a real assertion for a sign-in challenge. */
function assertLogin(
  sim: SimAuthenticator,
  cred: RegisteredCredential,
  challenge: string,
  opts: { signCount?: number; origin?: string; uv?: boolean } = {},
) {
  const flags = FLAG_UP | (opts.uv === false ? 0 : FLAG_UV);
  const ad = authData(flags, opts.signCount ?? 1, undefined);
  const cd = clientData('webauthn.get', challenge, opts.origin ?? ORIGIN);
  const signed = Buffer.concat([ad, createHash('sha256').update(cd).digest()]);
  return {
    credentialId: cred.credentialId,
    authenticatorData: b64url(ad),
    clientDataJSON: b64url(cd),
    signature: b64url(sim.sign(signed)),
  };
}

async function main() {
  console.log('\n== OpenResidency WebAuthn step-up + assurance ==\n');
  const exp: CeremonyExpectations = { challenge: '', origin: ORIGIN, rpId: RP_ID, requireUserVerification: true };

  for (const make of [makeEd25519Authenticator, makeP256Authenticator]) {
    const sim = make();
    console.log(`-- ${sim.alg} authenticator --`);

    // Registration
    const regChallenge = b64url(randomBytes(32));
    const cred = registerAuthenticator(sim, regChallenge);
    check(`${sim.alg}: registration extracts the credential id and key`, !!cred.credentialId && cred.alg === sim.alg);
    check(`${sim.alg}: the COSE key decodes to a usable public JWK`, !!coseKeyToJwk(sim.coseKey).jwk.x);

    // Authentication -- the happy path
    const c1 = b64url(randomBytes(32));
    const ok = verifyAssertion(assertLogin(sim, cred, c1), cred, { ...exp, challenge: c1 });
    check(`${sim.alg}: a genuine passkey assertion verifies`, ok.ok, ok.reason);

    // Wrong origin -> phishing resistance
    const c2 = b64url(randomBytes(32));
    const phish = verifyAssertion(assertLogin(sim, cred, c2, { origin: 'https://evil.example' }), cred, { ...exp, challenge: c2 });
    check(`${sim.alg}: an assertion made on the WRONG origin is rejected (phishing-resistant)`, !phish.ok);

    // Wrong challenge -> replay resistance
    const stale = verifyAssertion(assertLogin(sim, cred, b64url(randomBytes(32))), cred, { ...exp, challenge: b64url(randomBytes(32)) });
    check(`${sim.alg}: an assertion for a DIFFERENT challenge is rejected (replay-resistant)`, !stale.ok);

    // Tampered signature
    const c3 = b64url(randomBytes(32));
    const a3 = assertLogin(sim, cred, c3);
    a3.signature = b64url(Buffer.concat([Buffer.from(a3.signature, 'base64url').subarray(0, -1), Buffer.from([0x00])]));
    check(`${sim.alg}: a tampered signature is rejected`, !verifyAssertion(a3, cred, { ...exp, challenge: c3 }).ok);

    // Missing user verification when required
    const c4 = b64url(randomBytes(32));
    const noUv = verifyAssertion(assertLogin(sim, cred, c4, { uv: false }), cred, { ...exp, challenge: c4 });
    check(`${sim.alg}: assertion without user verification is rejected when UV is required`, !noUv.ok);

    // Clone detection: a counter that does not advance past the stored one
    const stored: RegisteredCredential = { ...cred, signCount: 5 };
    const c5 = b64url(randomBytes(32));
    const regress = verifyAssertion(assertLogin(sim, stored, c5, { signCount: 3 }), stored, { ...exp, challenge: c5 });
    check(`${sim.alg}: a regressed signature counter is rejected (clone detection)`, !regress.ok && regress.reason === 'SIGN_COUNT_REGRESSION');

    // Credential-id mismatch
    const c6 = b64url(randomBytes(32));
    const wrongId = verifyAssertion({ ...assertLogin(sim, cred, c6), credentialId: b64url(randomBytes(16)) }, cred, { ...exp, challenge: c6 });
    check(`${sim.alg}: an assertion naming a different credential id is rejected`, !wrongId.ok);
    console.log('');
  }

  // --- Assurance model ------------------------------------------------------
  console.log('-- assurance levels --');
  check('otp alone is AAL1', assess(['otp']).aal === 1 && assess(['otp']).acr === 'urn:openresidency:aal1');
  check('a Verifiable Presentation is AAL2 (bound-key possession)', assess(['vp']).aal === 2);
  check('WebAuthn alone is AAL2 and phishing-resistant', assess(['webauthn']).aal === 2 && assess(['webauthn']).phishingResistant);
  check('WebAuthn + attested biometric is AAL3', assess(['webauthn', 'biometric']).aal === 3);
  check('AAL3 amr lists hardware key AND biometric', (() => { const a = assess(['webauthn', 'biometric']).amr; return a.includes('hwk') && a.includes('bio'); })());
  check('biometric alone does NOT reach AAL3 without a possession factor', assess(['biometric']).aal === 1);
  check('an RP requiring aal2 is satisfied by WebAuthn', meetsRequirement(assess(['webauthn']), 'urn:openresidency:aal2'));
  check('an RP requiring aal3 is NOT satisfied by a one-time code', !meetsRequirement(assess(['otp']), 'urn:openresidency:aal3'));

  // --- Attested biometric match via the pluggable port ----------------------
  console.log('\n-- attested biometric match (mock authority) --');
  const matcher = new MockBiometricMatcher();
  const good = await matcher.match({ residentId: 'KT-1', modality: 'face', sample: 'match:KT-1' });
  check('the authority attests a matching capture', good.matched && (good.score ?? 0) > 0.9);
  const bad = await matcher.match({ residentId: 'KT-1', modality: 'face', sample: 'match:SOMEONE-ELSE' });
  check('a non-matching capture is a clean non-match, not an error', !bad.matched && bad.reason === 'NO_MATCH');
  check('the match carries the attesting source for audit', good.source === 'mock-biometric-authority');

  // The step-up as it would be composed at sign-in: WebAuthn possession + attested match.
  const sim = makeEd25519Authenticator();
  const cred = registerAuthenticator(sim, b64url(randomBytes(32)));
  const c = b64url(randomBytes(32));
  const passkeyOk = verifyAssertion(assertLogin(sim, cred, c), cred, { ...exp, challenge: c }).ok;
  const bioOk = (await matcher.match({ residentId: 'KT-1', modality: 'face', sample: 'match:KT-1' })).matched;
  const level = assess([...(passkeyOk ? ['webauthn' as const] : []), ...(bioOk ? ['biometric' as const] : [])]);
  check('a passkey + attested biometric sign-in composes to AAL3', level.aal === 3 && level.acr === 'urn:openresidency:aal3');

  // authenticatorData parser sanity
  check('parseAuthenticatorData reads the UV flag', parseAuthenticatorData(authData(FLAG_UP | FLAG_UV, 7)).uv === true);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
