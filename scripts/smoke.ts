/* eslint-disable no-console */
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { StatusList } from '../src/core/credentials/status-list';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { encodeCredentialQr } from '../src/core/offline/qr';
import { handleUssd } from '../src/core/offline/ussd';
import { AuditLog, InMemoryAuditStore } from '../src/core/audit/audit-log';
import { ConsentService, InMemoryConsentStore } from '../src/core/consent/consent';
import { jwtVerify } from 'jose';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
    console.log(`  \u2713 ${name}`);
  } else {
    fail++;
    console.log(`  \u2717 ${name}`);
  }
}

async function main() {
  console.log('\n== OpenResidency core smoke test ==\n');

  // --- Issuer key + DID (did:key => fully offline-verifiable) ---
  const key = await KeyStore.generate('issuer-key-1');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  console.log('Issuer DID (did:key):', issuerDid.slice(0, 48) + '...');

  // --- Country config: a subnational deployment using the MOCK provider ---
  const cfg: CountryConfig = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid,
      issuerName: 'Katsina State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 1095,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });

  const registry = new ProviderRegistry('unit-test-pepper');
  const issuer = new VcIssuer(key);
  const store = new InMemoryStore();
  const statusUrl = 'https://id.katsina.gov.ng/status/ng.json';
  const svc = new ResidencyService(registry, issuer, store, () => statusUrl);

  // --- Issue residency for a citizen who passes foundational check (even last digit) ---
  const good = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902', givenName: 'Amina', familyName: 'Bello' },
    holderId: undefined,
  });
  check('foundational-pass issues residency', good.status === 'issued');
  const jwt = good.status === 'issued' ? good.credentialJwt : '';
  const residentId = good.status === 'issued' ? good.residentId : '';
  console.log('  residentId:', residentId, '| credential bytes:', jwt.length);

  // --- Idempotency: same subject does not get a second residency ---
  const again = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902', givenName: 'Amina', familyName: 'Bello' },
  });
  check('same person is idempotent (no duplicate)', again.status === 'exists');

  // --- Foundational rejection (odd last digit) ---
  const bad = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678901' },
  });
  check('foundational-fail is rejected', bad.status === 'rejected');

  // --- OFFLINE verification with only the cached issuer public key ---
  const trust = new Map<string, TrustedIssuer>();
  trust.set(issuerDid, { did: issuerDid, publicJwk: key.publicJwk, statusLists: {} });
  const verifier = new VcVerifier(trust);

  const v1 = await verifier.verify(jwt, { offline: true });
  check('offline verify succeeds (signature + expiry)', v1.valid === true);
  check('verified subject carries residentId', (v1.subject as any)?.residentId === residentId);

  // --- Tamper detection ---
  const tampered = jwt.slice(0, -4) + (jwt.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
  const vTamper = await verifier.verify(tampered, { offline: true });
  check('tampered credential fails verification', vTamper.valid === false);

  // --- Untrusted issuer rejected ---
  const emptyVerifier = new VcVerifier(new Map());
  const vUntrusted = await emptyVerifier.verify(jwt, { offline: true });
  check('unknown issuer is rejected', vUntrusted.valid === false && vUntrusted.reason === 'UNTRUSTED_ISSUER');

  // --- Revocation, then offline check against cached status snapshot ---
  await svc.revoke(cfg, residentId);
  const snapshot = await store.loadStatusList('NG');
  const encoded = snapshot.encode();
  // Verifier syncs the published status list (here we hand it the snapshot).
  trust.get(issuerDid)!.statusLists = { [statusUrl]: StatusList.fromEncoded(encoded) };

  const v2 = await verifier.verify(jwt, { offline: true });
  check('revoked credential fails offline revocation check', v2.valid === false && v2.reason === 'REVOKED');
  check('revocation check actually ran', v2.checkedRevocation === true);

  // --- Offline QR carriage ---
  const qr = await encodeCredentialQr(jwt, { residentId, integrity: 'abc123' });
  check('credential fits in a single scannable QR', qr.mode === 'full');
  check('QR renders as SVG', qr.svg.startsWith('<svg'));

  // --- USSD feature-phone menu ---
  const menu = handleUssd('');
  check('USSD root menu offered to feature phones', menu.message.includes('Check my residency'));
  const otp = handleUssd(`2*${residentId}`);
  check('USSD login-code path triggers OTP action', otp.action?.type === 'sendOtp');

  // --- Audit framework: append-only hash chain ---
  const audit = new AuditLog(new InMemoryAuditStore());
  await audit.record({ action: 'identity.verify', actor: 'citizen', outcome: 'success' });
  await audit.record({ action: 'residency.issue', actor: 'citizen', target: residentId, outcome: 'success' });
  await audit.record({ action: 'consent.grant', actor: residentId, target: 'health', outcome: 'success' });
  const chain = await audit.verifyChain();
  check('audit chain verifies intact', chain.ok === true && chain.length === 3);

  // Tamper with a stored event and confirm the chain breaks.
  const store2 = new InMemoryAuditStore();
  const audit2 = new AuditLog(store2);
  await audit2.record({ action: 'residency.issue', actor: 'citizen', outcome: 'success' });
  await audit2.record({ action: 'residency.revoke', actor: 'admin', outcome: 'success' });
  const all = await store2.all();
  (all[0] as any).outcome = 'failure'; // silent after-the-fact edit
  const broken = await audit2.verifyChain();
  check('audit chain detects tampering', broken.ok === false && broken.brokenAtSeq === 0);

  // --- Consent framework: grant, receipt, idempotency, revoke ---
  const consent = new ConsentService(new InMemoryConsentStore(), key, issuerDid);
  const g1 = await consent.grant({
    subjectRef: 'subject-abc',
    residentId,
    relyingParty: 'health',
    purpose: 'Enrol in state health scheme',
    scopes: ['residency', 'health'],
  });
  check('consent grant returns a record and receipt', !!g1.record.id && g1.receipt.split('.').length === 3);

  // The signed receipt verifies offline against the issuer public key.
  const rverify = await jwtVerify(g1.receipt, key.publicKey, { issuer: issuerDid }).then(
    () => true,
    () => false,
  );
  check('consent receipt verifies with issuer key', rverify === true);

  const g2 = await consent.grant({
    subjectRef: 'subject-abc',
    residentId,
    relyingParty: 'health',
    purpose: 'Enrol in state health scheme',
    scopes: ['residency', 'health'],
  });
  check('identical consent is idempotent (same record)', g2.record.id === g1.record.id);

  const revoked = await consent.revoke(g1.record.id);
  check('consent can be revoked', revoked?.status === 'revoked');
  const afterList = await consent.listByResident(residentId);
  check('revoked consent is reflected in listing', afterList.some((c) => c.status === 'revoked'));

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
