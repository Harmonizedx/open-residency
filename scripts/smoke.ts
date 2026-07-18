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
import { generateResidentId, isValidResidentId, IdFormat } from '../src/core/residency/resident-id';
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

  // --- Applicant -> identity binding is recorded, and asserted in the credential ---
  // The MOCK provider is a bare lookup, so it attests NO binding: a passed lookup is not
  // owner proof, and the credential must say so rather than imply ownership.
  check(
    'lookup-only issuance records binding method "none"',
    good.status === 'issued' && good.record.binding.method === 'none',
  );
  check(
    'credential asserts applicantBinding to the verifier',
    (v1.subject as any)?.applicantBinding?.method === 'none',
  );

  // A config with no residence policy records residence as self-declared (RAL0) and never
  // gates on it -- the pre-existing behaviour, now made explicit on the credential.
  check(
    'default config records self-declared residence (RAL0)',
    good.status === 'issued' &&
      good.record.residence.assuranceLevel === 'RAL0' &&
      good.record.residence.method === 'self_declared',
  );
  check(
    'credential asserts the residence block',
    (v1.subject as any)?.residence?.assuranceLevel === 'RAL0',
  );

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

  // A consent created through the SSO step records the grant it authorizes, so that
  // withdrawing it can revoke the session rather than only noting the withdrawal. Signing
  // in again reuses the record, and the record must then track the CURRENT grant -- a
  // stale id would revoke a dead grant and leave the live one releasing claims.
  const gs1 = await consent.grant({
    subjectRef: 'subject-sso',
    residentId: 'KT-SSO-0001-X',
    relyingParty: 'tax',
    purpose: 'Sign in',
    scopes: ['residency', 'tax'],
    grantId: 'grant-first',
  });
  check('consent records the OIDC grant it authorized', gs1.record.grantId === 'grant-first');
  const gs2 = await consent.grant({
    subjectRef: 'subject-sso',
    residentId: 'KT-SSO-0001-X',
    relyingParty: 'tax',
    purpose: 'Sign in',
    scopes: ['residency', 'tax'],
    grantId: 'grant-second',
  });
  check(
    'reusing a consent adopts the current grant instead of keeping a stale one',
    gs2.record.id === gs1.record.id && gs2.record.grantId === 'grant-second',
  );

  const revoked = await consent.revoke(g1.record.id);
  check('consent can be revoked', revoked?.status === 'revoked');
  const afterList = await consent.listByResident(residentId);
  check('revoked consent is reflected in listing', afterList.some((c) => c.status === 'revoked'));

  // --- Binding policy: a jurisdiction that REQUIRES owner binding refuses a bare lookup ---
  const boundCfg: CountryConfig = parseCountryConfig({
    countryCode: 'KE',
    countryName: 'Kenya',
    defaultSubnationalUnit: 'NBI',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'id', label: 'ID' }],
      assuranceOnSuccess: 'verified',
    },
    // Owner binding is required; only an in-person comparison is accepted here.
    residency: {
      minAssurance: 'verified',
      proofOfResidence: 'attestation',
      applicantBinding: { required: true, acceptedMethods: ['attended_comparison'] },
    },
    credential: {
      issuerDid,
      issuerName: 'Nairobi County Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'NBI', name: 'Nairobi', parent: 'KE', level: 'county' }],
  });
  const boundStore = new InMemoryStore();
  const boundSvc = new ResidencyService(
    registry,
    issuer,
    boundStore,
    () => 'https://id.nairobi.go.ke/status/ke.json',
  );

  const unbound = await boundSvc.issue(boundCfg, {
    countryCode: 'KE',
    subnationalUnit: 'NBI',
    identifiers: { id: '22222222222' }, // even => foundational match, but nobody bound the applicant
  });
  check(
    'binding-required jurisdiction rejects an unbound applicant',
    unbound.status === 'rejected' && unbound.reason === 'APPLICANT_BINDING_REQUIRED_NONE',
  );

  const bound = await boundSvc.issue(boundCfg, {
    countryCode: 'KE',
    subnationalUnit: 'NBI',
    identifiers: { id: '22222222222' },
    // An enrolment agent compared the applicant to the identity evidence in person.
    binding: { method: 'attended_comparison', ref: 'agent-4417' },
  });
  check('same applicant issues once bound in person', bound.status === 'issued');
  check(
    'issued record carries the binding method',
    bound.status === 'issued' && bound.record.binding.method === 'attended_comparison',
  );
  const boundVerify =
    bound.status === 'issued' ? await verifier.verify(bound.credentialJwt, { offline: true }) : null;
  check(
    'credential asserts the attended_comparison binding',
    (boundVerify?.subject as any)?.applicantBinding?.method === 'attended_comparison',
  );

  // --- Proof-of-residence policy: enforced, origin never counts as residence ----------
  //
  // A jurisdiction that REQUIRES RAL2 residence. The foundational record is auto-collected
  // (register-declared residence, capped RAL1) and must reconcile to the claimed unit;
  // reaching RAL2 needs an authority attestation on top. Origin is deliberately different
  // from residence here, to prove the engine never uses origin to satisfy residence.
  const resCfg: CountryConfig = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN' }],
      assuranceOnSuccess: 'verified',
    },
    residency: {
      minAssurance: 'verified',
      proofOfResidence: 'attestation',
      residence: {
        required: true,
        targetLevel: 'RAL2',
        acceptedMethods: ['register_declared_residence', 'authority_attestation'],
        unitMatchRequired: true,
        acceptFoundationalResidence: true,
      },
    },
    credential: {
      issuerDid,
      issuerName: 'Katsina State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 1095,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [
      { code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' },
      { code: 'ZA', name: 'Zamfara', parent: 'NG', level: 'state' },
    ],
  });
  const resStore = new InMemoryStore();
  const resSvc = new ResidencyService(
    registry,
    issuer,
    resStore,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );

  // Applicant claims KT. Their NIN record says residence=Zamfara but origin=Katsina. If the
  // engine (wrongly) used origin, this would pass; because only residence counts, the
  // register evidence points at the wrong unit and RAL2 is not met.
  const originNotResidence = await resSvc.issue(resCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '10000000002', residenceUnit: 'ZA', originUnit: 'KT' },
  });
  check(
    'origin is never used to satisfy residence',
    originNotResidence.status === 'rejected' &&
      originNotResidence.reason!.startsWith('PROOF_OF_RESIDENCE_BELOW_RAL2'),
  );

  // NIN residence DOES match the claimed unit, but register-declared residence is capped at
  // RAL1 -- still short of the required RAL2 on its own.
  const registerOnly = await resSvc.issue(resCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '10000000004', residenceUnit: 'Katsina' },
  });
  check(
    'register-declared residence alone is capped at RAL1 (below required RAL2)',
    registerOnly.status === 'rejected' &&
      registerOnly.reason === 'PROOF_OF_RESIDENCE_BELOW_RAL2_GOT_RAL1',
  );

  // Add the ward operator's attestation and RAL2 is reached: issuance succeeds.
  const attested = await resSvc.issue(resCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '10000000006', residenceUnit: 'Katsina' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'Katsina', ref: 'ward-officer-77' }],
  });
  check('authority attestation lifts residence to RAL2 and issues', attested.status === 'issued');
  check(
    'issued record carries the achieved residence (RAL2, attested, unit KT)',
    attested.status === 'issued' &&
      attested.record.residence.assuranceLevel === 'RAL2' &&
      attested.record.residence.method === 'authority_attestation' &&
      attested.record.residence.unit === 'KT',
  );
  const resVerify =
    attested.status === 'issued'
      ? await verifier.verify(attested.credentialJwt, { offline: true })
      : null;
  check(
    'credential asserts the achieved residence assurance to the verifier',
    (resVerify?.subject as any)?.residence?.assuranceLevel === 'RAL2',
  );

  // --- Configurable Resident ID format ------------------------------------------------
  //
  // The default is unchanged (KT-XXXX-XXXX-C, Crockford + check char). A state can instead
  // declare a statutory scheme -- here a 12-digit numeric KRID with a Luhn check.
  const defaultId = generateResidentId('KT');
  check('default id keeps the KT-XXXX-XXXX-C shape', /^KT-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]$/.test(defaultId));
  check('default id validates its own check char', isValidResidentId(defaultId));
  check(
    'a mistyped default check char is caught',
    !isValidResidentId(defaultId.slice(0, -1) + (defaultId.slice(-1) === 'Z' ? 'Y' : 'Z')),
  );

  const kridFormat: IdFormat = {
    alphabet: 'numeric',
    groups: [11],
    separator: '',
    case: 'upper',
    prefix: { mode: 'none' },
    checkDigit: { enabled: true, algorithm: 'luhn' },
  };
  const krid = generateResidentId('KT', kridFormat);
  check('numeric KRID renders as 12 digits', /^\d{12}$/.test(krid));
  check('numeric KRID passes its Luhn check', isValidResidentId(krid, kridFormat));
  check(
    'a single mistyped KRID digit is caught by Luhn',
    !isValidResidentId((krid[0] === '0' ? '1' : '0') + krid.slice(1), kridFormat),
  );

  // Config guardrails: entropy floor, and numeric-checksum/alphabet coherence.
  const idBase = {
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: { provider: 'MOCK', inputs: [], assuranceOnSuccess: 'verified' },
    credential: { issuerDid, issuerName: 'X', context: ['https://www.w3.org/ns/credentials/v2'] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  };
  const parseThrows = (residentId: unknown): boolean => {
    try {
      parseCountryConfig({ ...idBase, residentId });
      return false;
    } catch {
      return true;
    }
  };
  check('id config rejects a sub-entropy format', parseThrows({ alphabet: 'numeric', groups: [4], checkDigit: { enabled: false } }));
  check('id config rejects Luhn over a non-numeric alphabet', parseThrows({ alphabet: 'crockford32', checkDigit: { enabled: true, algorithm: 'luhn' } }));
  check(
    'id config accepts a valid 12-digit KRID ruleset',
    !parseThrows({ alphabet: 'numeric', groups: [11], separator: '', prefix: { mode: 'none' }, checkDigit: { enabled: true, algorithm: 'luhn' } }),
  );

  // End-to-end: issuance honours the configured format.
  const kridCfg: CountryConfig = parseCountryConfig({
    ...idBase,
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    residentId: { alphabet: 'numeric', groups: [11], separator: '', prefix: { mode: 'none' }, checkDigit: { enabled: true, algorithm: 'luhn' } },
    credential: { issuerDid, issuerName: 'Katsina State Residency Authority', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
    foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
  });
  const kridStore = new InMemoryStore();
  const kridSvc = new ResidencyService(registry, issuer, kridStore, () => 'https://id.katsina.gov.ng/status/ng.json');
  const kridIssue = await kridSvc.issue(kridCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  check(
    'issuance mints the configured 12-digit KRID',
    kridIssue.status === 'issued' &&
      /^\d{12}$/.test(kridIssue.residentId) &&
      isValidResidentId(kridIssue.residentId, kridCfg.residentId),
  );

  // Per-subnational override: two units in one country, each on its own format. KT keeps
  // the country default (Crockford, unit prefix); LA overrides to a 12-digit numeric KRID.
  const perUnitFormat = { alphabet: 'numeric', groups: [11], separator: '', prefix: { mode: 'none' }, checkDigit: { enabled: true, algorithm: 'luhn' } };
  const federCfg: CountryConfig = parseCountryConfig({
    ...idBase,
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    // Country default stays Crockford (residentId omitted); only LA overrides.
    credential: { issuerDid, issuerName: 'Nigeria Residency Authority', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
    foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
    subnationalUnits: [
      { code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' },
      { code: 'LA', name: 'Lagos', parent: 'NG', level: 'state', residentId: perUnitFormat },
    ],
  });
  const federStore = new InMemoryStore();
  const federSvc = new ResidencyService(registry, issuer, federStore, () => 'https://id.gov.ng/status/ng.json');
  const ktIssue = await federSvc.issue(federCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: '12345678902' } });
  const laIssue = await federSvc.issue(federCfg, { countryCode: 'NG', subnationalUnit: 'LA', identifiers: { nin: '12345678904' } });
  check(
    'unit without an override inherits the country-default format',
    ktIssue.status === 'issued' && /^KT-/.test(ktIssue.residentId) && isValidResidentId(ktIssue.residentId, federCfg.residentId),
  );
  check(
    'unit with an override mints its own format',
    laIssue.status === 'issued' && /^\d{12}$/.test(laIssue.residentId) && isValidResidentId(laIssue.residentId, federCfg.subnationalUnits[1].residentId!),
  );

  // The claimed subnational unit is request-controlled but is persisted, asserted into the
  // credential, and rendered in the admin console. It must be validated at the engine, not
  // just wherever it happens to be displayed -- output escaping is the second line of
  // defence, and only the second.
  const injection = await federSvc.issue(federCfg, {
    countryCode: 'NG',
    subnationalUnit: '<img src=x onerror=alert(1)>',
    identifiers: { nin: '12345678906' },
  });
  const unknownUnit = await federSvc.issue(federCfg, {
    countryCode: 'NG',
    subnationalUnit: 'ZZ',
    identifiers: { nin: '12345678908' },
  });
  check(
    'a subnational unit carrying markup is refused',
    injection.status === 'rejected' && injection.reason === 'INVALID_SUBNATIONAL_UNIT',
  );
  check(
    'a well-formed but undeclared subnational unit is refused',
    unknownUnit.status === 'rejected' && unknownUnit.reason === 'UNKNOWN_SUBNATIONAL_UNIT',
  );

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
