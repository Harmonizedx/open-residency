/* eslint-disable no-console */
/**
 * HSM issuance smoke test.
 *
 * Proves the property the whole Signer port exists for: this deployment can issue and
 * verify real credentials while the private key stays inside a hardware token and
 * cannot be read out of it.
 *
 * Runs against SoftHSM, which speaks the same PKCS#11 interface as production HSMs, so
 * the code path exercised here is the one a Thales or Utimaco deployment takes. Skips
 * cleanly (exit 0) when SoftHSM or the optional `pkcs11js` dependency is absent, so it
 * can sit in `npm test` without becoming a machine-specific failure.
 *
 * Set SOFTHSM2_CONF and PKCS11_LIBRARY to point at a token, or let it discover the
 * usual Homebrew/Linux install locations.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { jwtVerify, importJWK, KeyLike } from 'jose';
import { KeyStore } from '../src/core/credentials/keystore';
import { Pkcs11Signer, isSessionError } from '../src/core/credentials/signers/pkcs11-signer';
import { buildDidWebDocument, didKeyFromJwk } from '../src/core/credentials/did';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';

const ISSUER_DID = 'did:web:id.katsina.gov.ng';
const STATUS_URL = `https://id.katsina.gov.ng/.well-known/status/ng.json`;

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

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

const CANDIDATE_LIBS = [
  process.env.PKCS11_LIBRARY,
  '/opt/homebrew/lib/softhsm/libsofthsm2.so',
  '/usr/local/lib/softhsm/libsofthsm2.so',
  '/usr/lib/softhsm/libsofthsm2.so',
  '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
].filter(Boolean) as string[];

function findLibrary(): string | undefined {
  return CANDIDATE_LIBS.find((p) => existsSync(p));
}

/** Stand up a throwaway SoftHSM token, unless the caller pointed us at a real one. */
function ensureToken(pin: string): { ok: true; label: string } | { ok: false; why: string } {
  const label = process.env.PKCS11_TOKEN_LABEL ?? 'openresidency-test';
  if (process.env.PKCS11_TOKEN_LABEL && process.env.SOFTHSM2_CONF) {
    return { ok: true, label };
  }

  let softhsmUtil: string;
  try {
    softhsmUtil = execFileSync('which', ['softhsm2-util'], { encoding: 'utf8' }).trim();
  } catch {
    return { ok: false, why: 'softhsm2-util is not installed' };
  }

  const dir = join(tmpdir(), `openresidency-hsm-${process.pid}`);
  const tokens = join(dir, 'tokens');
  mkdirSync(tokens, { recursive: true });
  const conf = join(dir, 'softhsm2.conf');
  writeFileSync(conf, `directories.tokendir = ${tokens}\nobjectstore.backend = file\nlog.level = ERROR\n`);
  process.env.SOFTHSM2_CONF = conf;

  try {
    execFileSync(
      softhsmUtil,
      ['--init-token', '--free', '--label', label, '--so-pin', pin, '--pin', pin],
      { stdio: 'pipe' },
    );
  } catch (e) {
    return { ok: false, why: `could not initialise a SoftHSM token: ${(e as Error).message}` };
  }
  return { ok: true, label };
}

async function main() {
  console.log('\n== OpenResidency HSM issuance smoke test ==\n');

  const libraryPath = findLibrary();
  if (!libraryPath) {
    console.log('  - SKIPPED: no PKCS#11 library found (install softhsm, or set PKCS11_LIBRARY)\n');
    process.exit(0);
  }
  try {
    require('pkcs11js');
  } catch {
    console.log('  - SKIPPED: the optional `pkcs11js` dependency is not installed\n');
    process.exit(0);
  }

  const pin = process.env.PKCS11_PIN ?? '1234';
  const token = ensureToken(pin);
  if (!token.ok) {
    console.log(`  - SKIPPED: ${token.why}\n`);
    process.exit(0);
  }

  const cfg = {
    libraryPath,
    pin,
    tokenLabel: token.label,
    keyLabel: `issuer-${Date.now()}`,
    kid: 'hsm-key-1',
  };

  console.log(`Token: ${token.label}   Library: ${libraryPath}\n`);

  // --- Provision a key that cannot leave the token -------------------------
  const publicJwk = await Pkcs11Signer.provision(cfg);
  check('an Ed25519 key pair is generated inside the token', publicJwk.crv === 'Ed25519');
  check('the public key is retrievable', typeof publicJwk.x === 'string' && publicJwk.x!.length > 0);
  check('no private material is exposed in the public JWK', !('d' in publicJwk));

  const signer = await Pkcs11Signer.open(cfg);
  check('the signer opens against the provisioned key', signer.kid === 'hsm-key-1');
  check('the signer advertises EdDSA', signer.alg === 'EdDSA');

  const key = await KeyStore.fromSigner(signer);
  check('the issuer key carries no exportable private key', key.privateKey === undefined);
  check('the issuer key exposes the public half', key.publicJwk.x === publicJwk.x);

  // --- A signature made in the token verifies outside it -------------------
  const message = Buffer.from('canary');
  const signature = await signer.sign(message);
  check('the token returns a 64-byte Ed25519 signature', signature.length === 64);
  const pubKeyObject = createPublicKey({ key: publicJwk as any, format: 'jwk' });
  check(
    'node:crypto verifies a signature made inside the token',
    cryptoVerify(null, message, pubKeyObject, signature),
  );

  // --- End-to-end issuance through the HSM, via the real service ----------
  // Deliberately the same path production takes -- ResidencyService issuing both
  // formats -- rather than calling the issuers directly, so this exercises the wiring
  // and not just the primitives.
  const residents = new InMemoryStore();
  const residency = new ResidencyService(
    new ProviderRegistry('hsm-test-pepper'),
    new VcIssuer(key),
    residents,
    () => STATUS_URL,
    new LdpIssuer(key),
  );

  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  check('a resident is enrolled and issued with the key in the HSM', enrolled.status === 'issued');
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const record = (await residents.findByResidentId(enrolled.residentId))!;

  const holderKey = await KeyStore.generate('holder');
  const holderDid = didKeyFromJwk(holderKey.publicJwk);

  const jwt = (await residency.mintForHolder(CONFIG, record, holderDid, 'jwt_vc_json'))
    .credential as string;
  check('a VC-JWT is issued with the key in the HSM', typeof jwt === 'string');

  const verifyKey = (await importJWK(key.publicJwk, 'EdDSA')) as KeyLike;
  let jwtVerified = false;
  try {
    await jwtVerify(jwt, verifyKey, { issuer: ISSUER_DID });
    jwtVerified = true;
  } catch {
    jwtVerified = false;
  }
  check('the HSM-signed VC-JWT verifies against the published public key', jwtVerified);

  const trust = new Map<string, TrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicJwks: [key.publicJwk], statusLists: {} }],
  ]);
  const outcome = await new VcVerifier(trust).verify(jwt, { offline: true });
  check('the standard verifier accepts the HSM-issued credential', outcome.valid);

  const tampered = jwt.slice(0, -6) + 'AAAAAA';
  const tamperedOutcome = await new VcVerifier(trust).verify(tampered, { offline: true });
  check('a tampered HSM-issued credential is rejected', !tamperedOutcome.valid);

  // --- Data Integrity (ldp_vc) issuance through the HSM -------------------
  const signedLdp = (await residency.mintForHolder(CONFIG, record, holderDid, 'ldp_vc'))
    .credential as LdpCredential;
  check('a Data Integrity proof is produced by the HSM', !!signedLdp.proof?.proofValue);
  check(
    'the HSM-signed Data Integrity proof verifies',
    await LdpIssuer.verify(signedLdp, pubKeyObject),
  );
  const tamperedLdp = {
    ...signedLdp,
    credentialSubject: { ...(signedLdp.credentialSubject as object), residentId: 'KT-FORGED' },
  } as LdpCredential;
  check(
    'a tampered Data Integrity credential is rejected',
    !(await LdpIssuer.verify(tamperedLdp, pubKeyObject)),
  );

  // --- The custody property itself -----------------------------------------
  let exported = false;
  try {
    // Reaching into the binding deliberately: this is the check that the token would
    // refuse to hand over the key even to code that asks for it directly.
    const pkcs11js = require('pkcs11js');
    const p = new pkcs11js.PKCS11();
    p.load(libraryPath);
    p.C_Initialize();
    try {
      const slot = p.C_GetSlotList(true)[0];
      const session = p.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
      p.C_Login(session, pkcs11js.CKU_USER, pin);
      p.C_FindObjectsInit(session, [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_LABEL, value: cfg.keyLabel },
      ]);
      const handle = p.C_FindObjects(session);
      p.C_FindObjectsFinal(session);
      p.C_GetAttributeValue(session, handle, [{ type: pkcs11js.CKA_VALUE }]);
      exported = true;
    } finally {
      p.C_Finalize();
    }
  } catch {
    exported = false;
  }
  check('the private key CANNOT be extracted from the token', !exported);

  // --- Rotation: a credential outlives the key that signed it --------------
  const rotated = await KeyStore.generate('hsm-key-2');
  const rotatedTrust = new Map<string, TrustedIssuer>([
    [
      ISSUER_DID,
      { did: ISSUER_DID, publicJwks: [rotated.publicJwk, key.publicJwk], statusLists: {} },
    ],
  ]);
  const afterRotation = await new VcVerifier(rotatedTrust).verify(jwt, { offline: true });
  check('a credential still verifies after the issuer rotates keys', afterRotation.valid);

  const onlyNewTrust = new Map<string, TrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicJwks: [rotated.publicJwk], statusLists: {} }],
  ]);
  const dropped = await new VcVerifier(onlyNewTrust).verify(jwt, { offline: true });
  check('...and stops verifying if the retired key is dropped', !dropped.valid);

  const didDoc = buildDidWebDocument('did:web:id.katsina.gov.ng', [rotated.publicJwk, key.publicJwk]);
  check(
    'the DID document publishes both the current and the retired key',
    (didDoc.verificationMethod as unknown[]).length === 4,
  );

  // --- Resilience: a PKCS#11 session is not durable ------------------------
  //
  // HSMs time out idle sessions, network HSMs reconnect, and appliances restart or fail
  // over. Everything this deployment signs goes through one signer, so a session that
  // cannot be recovered is a total issuance outage until someone restarts the process.
  // Dropping the session out from under the signer is the only way to test that, and it
  // means reaching into the binding -- deliberately, as the extraction check above does.
  const innards = signer as unknown as { binding: { p: any }; session: Buffer };
  const dropSession = () => innards.binding.p.C_CloseSession(innards.session);
  const verifyWith = (msg: string, sig: Uint8Array) =>
    cryptoVerify(null, Buffer.from(msg), pubKeyObject, Buffer.from(sig));

  dropSession();
  const afterDrop = await signer.sign(new TextEncoder().encode('after-drop'));
  check('the signer RECOVERS from a dropped session', verifyWith('after-drop', afterDrop));

  dropSession();
  await signer.sign(new TextEncoder().encode('again'));
  dropSession();
  const afterSecond = await signer.sign(new TextEncoder().encode('after-second-drop'));
  check('...and recovers repeatedly', verifyWith('after-second-drop', afterSecond));

  // C_SignInit and C_Sign are two calls sharing one session's mechanism state. If they
  // interleave, each signature runs under the other caller's init -- which does not throw,
  // it silently signs the wrong bytes.
  //
  // Be clear about what this check is and is not worth. Every step of the signing path is
  // synchronous today -- signOnce() and recover() both -- so a batch runs to completion
  // without ever yielding, and this passes with the queue in sign() removed. It was
  // mutation-tested: deleting the serialisation does not fail it. It earns its place as
  // the regression guard for the day someone introduces a suspension point (a retry
  // backoff, an async KMS call, a health check), because that is the change that turns
  // this from a passing test into a failing one -- and wrong-data signatures are not
  // something to discover in production.
  dropSession();
  const batch = Array.from({ length: 12 }, (_, i) => `concurrent-${i}`);
  const sigs = await Promise.all(batch.map((m) => signer.sign(new TextEncoder().encode(m))));
  check(
    'concurrent signatures across a recovery each verify over their own data',
    sigs.every((sig, i) => verifyWith(batch[i], sig)),
  );
  check(
    'and no two of them are the same signature',
    new Set(sigs.map((s) => Buffer.from(s).toString('hex'))).size === batch.length,
  );

  // Recovery must not launder a genuine refusal into a retry.
  check(
    'a lost session is treated as recoverable',
    isSessionError(new Error('CKR_SESSION_HANDLE_INVALID')),
  );
  check(
    'a bad PIN or key handle is NOT',
    !isSessionError(new Error('CKR_PIN_INCORRECT')) &&
      !isSessionError(new Error('CKR_KEY_HANDLE_INVALID')),
  );

  await signer.close();
  check('the HSM session closes cleanly', true);

  // --- Recovery fails shut if the key changed underneath -------------------
  //
  // A dropped session can mean the token restarted; it can also mean it was
  // re-provisioned. Signing on with a key other than the one already published in the DID
  // document would mint credentials that verify for nobody, and the only people who would
  // notice are the relying parties rejecting them. `rotated` stands in for a published key
  // that no longer matches what the token holds.
  const impostor = await Pkcs11Signer.open({ ...cfg, publicJwk: rotated.publicJwk });
  const impostorInnards = impostor as unknown as { binding: { p: any }; session: Buffer };
  impostorInnards.binding.p.C_CloseSession(impostorInnards.session);
  let refusal = '';
  try {
    await impostor.sign(new TextEncoder().encode('should-never-be-signed'));
  } catch (e) {
    refusal = (e as Error).message;
  }
  check(
    'recovery REFUSES to sign when the token holds a different key',
    refusal.includes('changed while this signer was open'),
  );
  await impostor.close().catch(() => undefined);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});