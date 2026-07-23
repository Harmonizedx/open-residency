/* eslint-disable no-console */
/**
 * WebAuthnService flow: registration (authorized by an existing factor), authentication,
 * and every challenge-lifecycle guard, against a simulated authenticator.
 *
 * webauthn-smoke.ts proves the ceremony CRYPTO. This proves the SERVICE around it: that a
 * challenge is single-use, time-bound, purpose-bound and resident-bound; that a registered
 * passkey then authenticates; that the clone counter is persisted; and that the
 * registration-authorization boundary holds (the service issues a registration challenge
 * only for the resident the caller names, and the controller gates that on a proven
 * factor -- exercised end-to-end in the Postgres e2e).
 */
import { generateKeyPairSync, sign as edSign, createSign, createHash, randomBytes, KeyObject } from 'node:crypto';
import {
  WebAuthnService,
  InMemoryWebAuthnChallengeStore,
  InMemoryWebAuthnCredentialStore,
} from '../src/core/sso/webauthn-service';

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

const RP = { rpId: 'id.katsina.gov.ng', origin: 'https://id.katsina.gov.ng', rpName: 'Katsina Residency' };
const RESIDENT = 'KT-7F3A-9K2P';
const b64url = (b: Buffer): string => b.toString('base64url');

// --- CBOR encode (COSE key) + simulated authenticator (shared shape with webauthn-smoke) ---
function cborUint(n: number): Buffer {
  if (n < 24) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x18, n]);
  return Buffer.from([0x19, n >> 8, n & 0xff]);
}
function cborInt(n: number): Buffer {
  if (n >= 0) return cborUint(n);
  const u = cborUint(-1 - n);
  u[0] |= 0x20;
  return u;
}
function cborBytes(b: Buffer): Buffer {
  const h = cborUint(b.length);
  h[0] |= 0x40;
  return Buffer.concat([h, b]);
}
function cborMap(pairs: [number, Buffer][]): Buffer {
  const h = cborUint(pairs.length);
  h[0] |= 0xa0;
  return Buffer.concat([h, ...pairs.map(([k, v]) => Buffer.concat([cborInt(k), v]))]);
}

interface Sim {
  key: KeyObject;
  coseKey: Buffer;
  credentialId: Buffer;
  sign(d: Buffer): Buffer;
}
function makeEd25519(): Sim {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = Buffer.from((publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url');
  return {
    key: privateKey,
    coseKey: cborMap([[1, cborInt(1)], [3, cborInt(-8)], [-1, cborInt(6)], [-2, cborBytes(x)]]),
    credentialId: randomBytes(16),
    sign: (d) => edSign(null, d, privateKey),
  };
}

const rpIdHash = () => createHash('sha256').update(RP.rpId, 'utf8').digest();
function authData(flags: number, signCount: number, attested?: Sim): Buffer {
  const head = Buffer.concat([rpIdHash(), Buffer.from([flags]), Buffer.alloc(4)]);
  head.writeUInt32BE(signCount, 33);
  if (!attested) return head;
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(attested.credentialId.length, 0);
  return Buffer.concat([head, Buffer.alloc(16), idLen, attested.credentialId, attested.coseKey]);
}
const clientData = (type: string, challenge: string, origin = RP.origin) =>
  Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8');

const UP = 0x01, UV = 0x04, AT = 0x40;

function makeRegistration(sim: Sim, challenge: string) {
  return {
    authData: b64url(authData(UP | UV | AT, 0, sim)),
    clientDataJSON: b64url(clientData('webauthn.create', challenge)),
  };
}
function makeAssertion(sim: Sim, credentialId: string, challenge: string, signCount = 1) {
  const ad = authData(UP | UV, signCount);
  const cd = clientData('webauthn.get', challenge);
  const signed = Buffer.concat([ad, createHash('sha256').update(cd).digest()]);
  return { credentialId, authenticatorData: b64url(ad), clientDataJSON: b64url(cd), signature: b64url(sim.sign(signed)) };
}

async function main() {
  console.log('\n== OpenResidency WebAuthn service (registration + authentication flow) ==\n');

  // A controllable clock, to test challenge expiry deterministically.
  let clock = 1_000_000_000_000;
  const challenges = new InMemoryWebAuthnChallengeStore();
  const creds = new InMemoryWebAuthnCredentialStore();
  const svc = new WebAuthnService(RP, challenges, creds, () => clock);

  // --- Registration (authorized by the caller having proven the resident) ---
  const sim = makeEd25519();
  const reg = await svc.startRegistration(RESIDENT);
  check('startRegistration issues creation options with a challenge', typeof reg.challengeId === 'string' && !!(reg.options as any).challenge);
  check('the options request user verification (two-factor on-device)', (reg.options as any).authenticatorSelection.userVerification === 'required');
  check('the options offer EdDSA and ES256', JSON.stringify((reg.options as any).pubKeyCredParams).includes('-8') && JSON.stringify((reg.options as any).pubKeyCredParams).includes('-7'));

  const regResult = await svc.finishRegistration(reg.challengeId, RESIDENT, makeRegistration(sim, (reg.options as any).challenge));
  check('finishRegistration verifies the attestation and persists the credential', regResult.ok === true);
  check('the credential is now listed for the resident', (await creds.listForResident(RESIDENT)).length === 1);

  // A registration challenge cannot be replayed
  const replayReg = await svc.finishRegistration(reg.challengeId, RESIDENT, makeRegistration(sim, (reg.options as any).challenge));
  check('a registration challenge cannot be reused', replayReg.ok === false && (replayReg as any).reason === 'CHALLENGE_ALREADY_USED');

  // --- Authentication -------------------------------------------------------
  const auth = await svc.startAuthentication(RESIDENT);
  check('startAuthentication returns the resident\'s credentials to sign', !!auth && (auth.options as any).allowCredentials.length === 1);
  const authRes = await svc.finishAuthentication(auth!.challengeId, makeAssertion(sim, regResult.ok ? regResult.credentialId : '', (auth!.options as any).challenge, 5));
  check('a genuine passkey assertion authenticates the resident', authRes.ok === true && (authRes as any).residentId === RESIDENT);
  check('the signature counter was advanced (clone detection persists)', (await creds.findByCredentialId(sim ? (regResult as any).credentialId : ''))?.signCount === 5);

  // A resident with no passkey -> null (caller falls back to another factor)
  check('startAuthentication returns null for a resident with no passkey', (await svc.startAuthentication('KT-NOBODY')) === null);

  // --- Challenge lifecycle guards ------------------------------------------
  // Purpose binding: an auth challenge cannot be used to register, and vice versa.
  const a2 = await svc.startAuthentication(RESIDENT);
  const wrongPurpose = await svc.finishRegistration(a2!.challengeId, RESIDENT, makeRegistration(makeEd25519(), (a2!.options as any).challenge));
  check('an authentication challenge cannot be used for registration (purpose-bound)', wrongPurpose.ok === false && (wrongPurpose as any).reason === 'CHALLENGE_PURPOSE_MISMATCH');

  // Resident binding: challenge issued for one resident cannot finish for another.
  const r3 = await svc.startRegistration(RESIDENT);
  const wrongResident = await svc.finishRegistration(r3.challengeId, 'KT-OTHER', makeRegistration(makeEd25519(), (r3.options as any).challenge));
  check('a challenge issued for one resident cannot finish for another (resident-bound)', wrongResident.ok === false && (wrongResident as any).reason === 'CHALLENGE_RESIDENT_MISMATCH');

  // Expiry.
  const r4 = await svc.startRegistration(RESIDENT);
  clock += 301_000; // past the 300s TTL
  const expired = await svc.finishRegistration(r4.challengeId, RESIDENT, makeRegistration(makeEd25519(), (r4.options as any).challenge));
  check('an expired challenge is rejected (time-bound)', expired.ok === false && (expired as any).reason === 'CHALLENGE_EXPIRED');
  clock -= 301_000;

  // Wrong-origin assertion at the service layer (phishing resistance end to end).
  const a5 = await svc.startAuthentication(RESIDENT);
  const phishAd = authData(UP | UV, 9);
  const phishCd = clientData('webauthn.get', (a5!.options as any).challenge, 'https://evil.example');
  const phishSigned = Buffer.concat([phishAd, createHash('sha256').update(phishCd).digest()]);
  const phish = await svc.finishAuthentication(a5!.challengeId, {
    credentialId: (regResult as any).credentialId,
    authenticatorData: b64url(phishAd),
    clientDataJSON: b64url(phishCd),
    signature: b64url(sim.sign(phishSigned)),
  });
  check('an assertion from the wrong origin is rejected by the service (phishing-resistant)', phish.ok === false);

  // Unknown credential.
  const a6 = await svc.startAuthentication(RESIDENT);
  const unknown = await svc.finishAuthentication(a6!.challengeId, makeAssertion(makeEd25519(), b64url(randomBytes(16)), (a6!.options as any).challenge));
  check('an assertion naming an unregistered credential is rejected', unknown.ok === false && (unknown as any).reason === 'UNKNOWN_CREDENTIAL');

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});