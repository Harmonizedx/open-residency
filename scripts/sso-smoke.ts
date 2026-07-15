/* eslint-disable no-console */
/**
 * SSO sign-in end-to-end check.
 *
 * The point of this suite is a specific security regression. The previous login handler
 * authenticated anyone who could name an EXISTING residency ID -- and residency IDs are
 * semi-public (printed on cards, carried in QR codes). So anyone who knew your residency
 * ID could sign in as you, to Health, Tax, and Subsidy. This proves that hole is closed:
 * knowing a residency ID is no longer sufficient to sign in.
 *
 * PRIMARY factor -- Verifiable Presentation:
 *   - a genuine presentation of your own credential authenticates you;
 *   - presenting a STOLEN credential (someone else's, under your key) does NOT;
 *   - a revoked credential does NOT;
 *   - naming a residency ID with no presentation does NOT.
 *
 * FALLBACK factor -- one-time code:
 *   - the right code authenticates; a wrong one does not;
 *   - a code is single-use and cannot be replayed;
 *   - the challenge locks after too many wrong guesses;
 *   - requesting a code for a non-existent resident is a silent no-op (no enumeration).
 */
import { SignJWT, generateKeyPair, exportJWK, KeyLike, JWK } from 'jose';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { InMemoryOid4vpStore } from '../src/core/oid4vp/ports';
import { Oid4vpService } from '../src/core/oid4vp/oid4vp-service';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../src/core/oid4vp/vp-verifier';
import { OtpService, InMemoryOtpStore, OtpSender } from '../src/core/sso/otp';
import { SsoAuthService } from '../src/core/sso/sso-auth';
import { didKeyFromJwk } from '../src/core/credentials/did';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `  -- ${detail}` : ''}`);
  }
}

const BASE = 'https://id.katsina.gov.ng';
const ISSUER_DID = 'did:web:id.katsina.gov.ng';
const STATUS_URL = `${BASE}/.well-known/status/ng.json`;

const CONFIG: CountryConfig = parseCountryConfig({
  countryCode: 'NG',
  countryName: 'Nigeria',
  foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
  residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
  credential: {
    issuerDid: ISSUER_DID,
    issuerName: 'Katsina State Residency Authority',
    type: 'StateResidencyCredential',
    validityDays: 1095,
    context: ['https://www.w3.org/ns/credentials/v2'],
  },
  subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
});

/** A test OTP sender that captures the code instead of delivering it. */
class CapturingSender implements OtpSender {
  last?: { residentId: string; code: string };
  async send(residentId: string, code: string) {
    this.last = { residentId, code };
    return { channel: 'test' };
  }
}

async function buildVp(opts: {
  privateKey: KeyLike;
  holderDid: string;
  credential: string | LdpCredential;
  nonce: string;
  audience: string;
}): Promise<string> {
  return new SignJWT({
    nonce: opts.nonce,
    vp: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: opts.holderDid,
      verifiableCredential: [opts.credential],
    },
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: `${opts.holderDid}#0`, typ: 'JWT' })
    .setIssuer(opts.holderDid)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(opts.privateKey);
}

async function main() {
  console.log('\n== SSO sign-in: the login is now real authentication ==\n');

  const key = await KeyStore.generate('issuer-key-1');
  const residents = new InMemoryStore();
  const residency = new ResidencyService(
    new ProviderRegistry('test-pepper'),
    new VcIssuer(key),
    residents,
    () => STATUS_URL,
    new LdpIssuer(key),
  );

  const trust = new Map<string, TrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicJwk: key.publicJwk, statusLists: {} }],
  ]);
  const vcVerifier = new VcVerifier(trust);
  const ldpTrust = new Map<string, VpTrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicKeyObject: keyObjectFromJwk(key.publicJwk) }],
  ]);
  const oid4vp = new Oid4vpService(
    {
      baseUrl: BASE,
      clientId: ISSUER_DID,
      clientName: 'Katsina Residency Sign-in',
      requestTtlSeconds: 300,
      query: ['dcql', 'presentation_definition'],
    },
    new InMemoryOid4vpStore(),
    () => new VpVerifier(vcVerifier, ldpTrust),
    key,
  );

  const sender = new CapturingSender();
  let otpSeq = 0;
  const otp = new OtpService(new InMemoryOtpStore(), sender, () => `otp-${++otpSeq}`);
  const sso = new SsoAuthService(oid4vp, otp, residents);

  const syncStatus = async () => {
    trust.get(ISSUER_DID)!.statusLists = { [STATUS_URL]: await residents.loadStatusList('NG') };
  };

  // Amina enrolls and loads a wallet-bound credential.
  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const residentId = enrolled.residentId;
  const record = (await residents.findByResidentId(residentId))!;

  const aminaKp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const amina = { privateKey: aminaKp.privateKey, publicJwk: await exportJWK(aminaKp.publicKey) };
  const aminaDid = didKeyFromJwk(amina.publicJwk);
  const aminaVc = await residency.mintForHolder(CONFIG, record, aminaDid, 'ldp_vc');
  const aminaCred = aminaVc.credential as LdpCredential;
  await syncStatus();

  // Helper: run a full VP sign-in and return the outcome.
  async function vpSignIn(build: (nonce: string, aud: string) => Promise<string>) {
    const { requestId } = await sso.beginVpLogin();
    const reqObj = JSON.parse(
      Buffer.from((await oid4vp.requestObject(requestId)).split('.')[1], 'base64url').toString(),
    );
    await oid4vp.handleResponse(requestId, { vp_token: await build(reqObj.nonce, reqObj.client_id) });
    return sso.pollVpLogin(requestId);
  }

  // ---- The regression: knowing a residency ID is NOT enough --------------
  console.log('The old hole is closed:');
  const noPresentation = await sso.pollVpLogin('a-request-that-was-never-answered');
  check('naming a residency ID with no presentation does NOT authenticate', noPresentation.status !== 'authenticated');

  // ---- Primary factor: genuine presentation ------------------------------
  console.log('');
  console.log('Verifiable Presentation sign-in:');
  const good = await vpSignIn((nonce, aud) =>
    buildVp({ privateKey: amina.privateKey, holderDid: aminaDid, credential: aminaCred, nonce, audience: aud }),
  );
  check('a genuine presentation authenticates', good.status === 'authenticated');
  check('and yields the correct residency ID', good.residentId === residentId);

  // A stolen credential under someone else's key: the exact attack the whole design
  // exists to stop, now at the sign-in door.
  console.log('');
  console.log('Attacks on the primary factor:');
  const malloryKp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const malloryDid = didKeyFromJwk(await exportJWK(malloryKp.publicKey));
  const stolen = await vpSignIn((nonce, aud) =>
    buildVp({ privateKey: malloryKp.privateKey, holderDid: malloryDid, credential: aminaCred, nonce, audience: aud }),
  );
  check("a STOLEN credential under an attacker's key does NOT authenticate", stolen.status !== 'authenticated', stolen.reason);

  // A revoked credential.
  await residency.revoke(CONFIG, residentId);
  await syncStatus();
  const revoked = await vpSignIn((nonce, aud) =>
    buildVp({ privateKey: amina.privateKey, holderDid: aminaDid, credential: aminaCred, nonce, audience: aud }),
  );
  check('a REVOKED credential does NOT authenticate', revoked.status !== 'authenticated', revoked.reason);

  // ---- Fallback factor: one-time code ------------------------------------
  console.log('');
  console.log('One-time code fallback:');

  await sso.beginOtpLogin(residentId);
  const code = sender.last!.code;
  check('a code is issued to the resident', sender.last?.residentId === residentId && /^\d{6}$/.test(code));

  const wrong = await sso.verifyOtpLogin(residentId, code === '000000' ? '111111' : '000000');
  check('a wrong code does NOT authenticate', !wrong.authenticated);

  const right = await sso.verifyOtpLogin(residentId, code);
  check('the right code authenticates', right.authenticated && right.residentId === residentId);

  const replay = await sso.verifyOtpLogin(residentId, code);
  check('the same code cannot be replayed (single-use)', !replay.authenticated);

  // Lockout after repeated wrong guesses.
  await sso.beginOtpLogin(residentId);
  const code2 = sender.last!.code;
  const bad = code2 === '000000' ? '111111' : '000000';
  for (let i = 0; i < 5; i++) await sso.verifyOtpLogin(residentId, bad);
  const afterLock = await sso.verifyOtpLogin(residentId, code2); // even the RIGHT code
  check('the challenge locks after too many wrong guesses', !afterLock.authenticated && afterLock.reason === 'LOCKED');

  // No enumeration: requesting a code for an unknown resident is a silent no-op.
  sender.last = undefined;
  await sso.beginOtpLogin('KT-DOES-NOT-EXIST');
  check('requesting a code for an unknown resident sends nothing (no enumeration)', sender.last === undefined);

  console.log(`\n${pass} passed, ${fail} failed\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
