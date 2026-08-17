/* eslint-disable no-console */
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { StatusList } from '../src/core/credentials/status-list';
import { LdpIssuer } from '../src/core/credentials/ldp-issuer';
import { StatusListPublisher } from '../src/core/credentials/status-list-publisher';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { generateResidentId, isValidResidentId, IdFormat } from '../src/core/residency/resident-id';
import { encodeCredentialQr } from '../src/core/offline/qr';
import { handleUssd } from '../src/core/offline/ussd';
import {
  AuditLog,
  InMemoryAuditStore,
  InMemoryAuditCheckpointStore,
  AuditEvent,
  AuditStore,
} from '../src/core/audit/audit-log';
import {
  ConsentPolicy,
  ConsentService,
  GrantInput,
  InMemoryConsentStore,
} from '../src/core/consent/consent';
import { LegalBasisRegistry, legalBasesForDeployment } from '../src/core/consent/legal-basis';
import { jwtVerify } from 'jose';

/**
 * ORCS §9 requires a controller, data categories, evidence of agreement and a resolvable
 * legal basis on every grant, and `grant()` refuses without them. This supplies defaults so
 * the assertions below stay about what they were testing -- expiry, idempotency, receipts --
 * and throws on refusal rather than returning it, because a refusal here is a broken test
 * rather than a case under test. `consent-smoke.ts` covers the refusals themselves.
 */
async function grantOk(
  svc: ConsentService,
  input: Omit<GrantInput, 'dataCategories' | 'evidence'> &
    Partial<Pick<GrantInput, 'dataCategories' | 'evidence'>>,
) {
  const out = await svc.grant({
    ...input,
    // After the spread, not before: an explicit `dataCategories: undefined` in the caller
    // would otherwise overwrite the default with undefined and refuse every grant.
    dataCategories: input.dataCategories ?? input.scopes,
    evidence: input.evidence ?? {
      method: 'operator_recorded',
      at: new Date().toISOString(),
      reference: `smoke:${input.residentId}:${input.relyingParty}`,
    },
  });
  if (!out.ok) throw new Error(`consent grant unexpectedly refused: ${out.reason}`);
  return out;
}

function testConsentPolicy(): ConsentPolicy {
  const controller = 'Katsina State Residency Authority';
  return {
    controller,
    legalBases: new LegalBasisRegistry(
      legalBasesForDeployment({ jurisdiction: 'Nigeria', controller }),
    ),
  };
}

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
  trust.set(issuerDid, { did: issuerDid, publicJwks: [key.publicJwk], statusLists: {} });
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

  // --- Published status list is signed, and re-signed only when it changes ---
  // The status endpoint is public and unauthenticated, and signing runs canonicalization
  // plus an issuer-key signature (an HSM/KMS call in production). Re-signing per request
  // would let a poll drive unbounded signs, so the publisher caches by encoded content:
  // an unchanged list returns the same signed credential; a changed one is re-signed.
  const publisher = new StatusListPublisher(new LdpIssuer(key));
  const slist = await store.loadStatusList('NG');
  const pub1 = await publisher.publish(statusUrl, issuerDid, slist);
  const pub2 = await publisher.publish(statusUrl, issuerDid, slist);
  check('published status list carries a proof', !!pub1.proof);
  check('unchanged status list is not re-signed (same cached credential)', pub1 === pub2);
  slist.set(50000, true); // mutate the list content
  const pub3 = await publisher.publish(statusUrl, issuerDid, slist);
  check(
    'a changed status list is re-signed',
    pub3.proof?.proofValue !== pub1.proof?.proofValue,
  );

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
  const consent = new ConsentService(new InMemoryConsentStore(), key, issuerDid, testConsentPolicy());
  const g1 = await grantOk(consent, {
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

  const g2 = await grantOk(consent, {
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
  const gs1 = await grantOk(consent, {
    subjectRef: 'subject-sso',
    residentId: 'KT-SSO-0001-X',
    relyingParty: 'tax',
    purpose: 'Sign in',
    scopes: ['residency', 'tax'],
    grantId: 'grant-first',
  });
  check('consent records the OIDC grant it authorized', gs1.record.grantId === 'grant-first');
  const gs2 = await grantOk(consent, {
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

  // --- A config that does not state its assurance is REFUSED, not defaulted ---
  //
  // `assuranceOnSuccess` was optional, and an omitted value resolved to 'verified' -- the
  // second-highest rung, reached by saying nothing. The value is released to every relying
  // party over SSO as `assurance_level`, so a deployment that never declared what its
  // identity source proves was silently credited with having proved a great deal. Only the
  // deployer knows what their register establishes, so there is no safe default: the config
  // must say, and is rejected at load if it does not.
  let refusedSilentAssurance = false;
  try {
    parseCountryConfig({
      countryCode: 'ZZ',
      countryName: 'Nowhere',
      defaultSubnationalUnit: 'DX',
      foundational: { provider: 'MOCK', inputs: [] }, // no assuranceOnSuccess
      residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
      credential: {
        issuerDid,
        issuerName: 'Test',
        type: 'StateResidencyCredential',
        validityDays: 365,
        context: ['https://www.w3.org/ns/credentials/v2'],
      },
      subnationalUnits: [{ code: 'DX', name: 'Demo', parent: 'ZZ', level: 'state' }],
    });
  } catch {
    refusedSilentAssurance = true;
  }
  check(
    'a config that omits assuranceOnSuccess is refused, never defaulted to "verified"',
    refusedSilentAssurance,
  );

  // --- Consent expiry is ENFORCED, not merely recorded (G-08) ---
  //
  // `expiresAt` was written at grant time and read nowhere, so a 30-day consent authorized
  // claim release for ever. Each assertion below fails on the pre-fix code, which is the
  // point: an expiry the system records but does not honour is worse than no expiry, because
  // the citizen was told it would lapse.
  const expiringStore = new InMemoryConsentStore();
  const expiring = new ConsentService(expiringStore, key, issuerDid, testConsentPolicy());
  const shortLived = await grantOk(expiring, {
    subjectRef: 'tok-expiry',
    residentId: 'NG-KT-EXPIRY',
    relyingParty: 'health',
    purpose: 'Eligibility check',
    scopes: ['openid', 'health'],
    validityDays: 30,
  });
  check('a consent with validityDays records an expiry', !!shortLived.record.expiresAt);
  check(
    'the receipt states the expiry, as a claim and as JWT `exp`',
    (() => {
      const payload = JSON.parse(
        Buffer.from(shortLived.receipt.split('.')[1], 'base64url').toString('utf8'),
      );
      return payload.expiresAt === shortLived.record.expiresAt && typeof payload.exp === 'number';
    })(),
  );

  const beforeLapse = new Date(Date.parse(shortLived.record.expiresAt!) - 1000);
  const afterLapse = new Date(Date.parse(shortLived.record.expiresAt!) + 1000);

  check(
    'before the expiry the consent is active',
    (await expiring.findActive('NG-KT-EXPIRY', 'health', beforeLapse))?.id === shortLived.record.id,
  );
  check(
    'after the expiry it no longer authorizes anything',
    (await expiring.findActive('NG-KT-EXPIRY', 'health', afterLapse)) === null,
  );
  check(
    'and the stored record converges to expired on that read',
    (await expiringStore.findById(shortLived.record.id))?.status === 'expired',
  );

  // The resurrection path: re-granting must not revive a lapsed consent by reusing it.
  const regrant = await grantOk(expiring, {
    subjectRef: 'tok-expiry',
    residentId: 'NG-KT-EXPIRY',
    relyingParty: 'health',
    purpose: 'Eligibility check',
    scopes: ['openid', 'health'],
    validityDays: 30,
  });
  check(
    'granting again after expiry creates a NEW consent, never resurrects the lapsed one',
    regrant.record.id !== shortLived.record.id && regrant.record.status === 'active',
  );

  // A grant with no expiry must be unaffected by any of the above.
  const perpetual = await grantOk(expiring, {
    subjectRef: 'tok-perpetual',
    residentId: 'NG-KT-PERPETUAL',
    relyingParty: 'tax',
    purpose: 'Assessment',
    scopes: ['openid', 'tax'],
  });
  check(
    'a consent granted with no expiry stays active indefinitely',
    (await expiring.findActive('NG-KT-PERPETUAL', 'tax', afterLapse))?.id === perpetual.record.id,
  );

  // The sweep, on a grant nobody has read: read-path enforcement is the guarantee, but the
  // register still has to be reconcilable on demand (a subject-access request, an export).
  const sweptGrant = await grantOk(expiring, {
    subjectRef: 'tok-sweep',
    residentId: 'NG-KT-SWEEP',
    relyingParty: 'permits',
    purpose: 'Permit application',
    scopes: ['openid', 'permits'],
    validityDays: 30,
  });
  const sweepAt = new Date(Date.parse(sweptGrant.record.expiresAt!) + 1000);
  const firstSweep = await expiring.expireDue('NG-KT-SWEEP', sweepAt);
  check(
    'the sweep transitions a lapsed grant nobody had read',
    firstSweep.length === 1 && firstSweep[0].status === 'expired',
  );
  check(
    'and is idempotent — a second sweep reports nothing left to change',
    (await expiring.expireDue('NG-KT-SWEEP', sweepAt)).length === 0,
  );
  check(
    'a lapsed grant is listed as expired, never as active',
    (await expiring.listByResident('NG-KT-SWEEP', sweepAt)).every((c) => c.status !== 'active'),
  );

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

  // --- Provisional issuance is reconciled, and does not stand forever -----------
  //
  // A record entered at a desk with no connectivity is issued on trust and flagged
  // provisional. Before reconcile() existed, nothing could ever clear that flag, so an
  // offline enrolment in a rural LGA stayed provisional permanently and "provisional"
  // and "verified" meant the same thing in practice.
  console.log('\nProvisional reconciliation:');
  {
    const pCfg: CountryConfig = parseCountryConfig({
      countryCode: 'NG',
      countryName: 'Nigeria',
      defaultSubnationalUnit: 'KT',
      foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
      residency: {
        minAssurance: 'verified',
        proofOfResidence: 'attestation',
        allowProvisional: true,
        provisionalMaxAgeDays: 30,
      },
      credential: { issuerDid, issuerName: 'Katsina State Residency Authority', context: ['https://www.w3.org/ns/credentials/v2'] },
      subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
    });
    const pStore = new InMemoryStore();
    const pSvc = new ResidencyService(new ProviderRegistry('smoke-pepper'), issuer, pStore, () => statusUrl);

    // MOCK verifies any identifier ending in an even digit, so both of these pass the
    // lookup -- they simply describe different people.
    const AMINA = '12345678902';
    const SOMEONE_ELSE = '12345678904';

    const offlineIssue = await pSvc.issue(pCfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: AMINA },
      context: { offline: true },
    });
    check('an offline enrolment is issued provisionally', offlineIssue.status === 'issued' && offlineIssue.record?.provisional === true);
    const pRid = offlineIssue.status === 'issued' ? offlineIssue.residentId : '';

    // A gateway that is down is an ABSENCE of a verdict, not a negative one: the record
    // must stay provisional rather than be treated as refuted.
    const unreachable = await pSvc.reconcile(pCfg, pRid, { nin: '12345678901' }); // odd -> no match
    check('a failed live check leaves the record provisional', unreachable.status === 'unconfirmed');
    check('and it really is still provisional', (await pStore.findByResidentId(pRid))?.provisional === true);

    // Verified, but as a different person: reported, never silently accepted.
    const wrongPerson = await pSvc.reconcile(pCfg, pRid, { nin: SOMEONE_ELSE });
    check('a live match for a DIFFERENT person is a mismatch, not a confirmation', wrongPerson.status === 'mismatch');
    check('a mismatch also leaves it provisional', (await pStore.findByResidentId(pRid))?.provisional === true);

    // The happy path: the live authority agrees this is the same person.
    const confirmed = await pSvc.reconcile(pCfg, pRid, { nin: AMINA });
    check('the live authority confirming the same subject clears provisional', confirmed.status === 'confirmed');
    check('the stored record is no longer provisional', (await pStore.findByResidentId(pRid))?.provisional === false);
    const again = await pSvc.reconcile(pCfg, pRid, { nin: AMINA });
    check('reconciling twice is idempotent', again.status === 'already-confirmed');

    // Unconfirmed records do not stand forever.
    const stale = await pSvc.issue(pCfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: '22345678902' },
      context: { offline: true },
    });
    const staleRid = stale.status === 'issued' ? stale.residentId : '';
    const notYet = await pSvc.expireProvisional(pCfg, { now: new Date() });
    check('a fresh provisional record is left alone', notYet.expired.length === 0);

    const later = new Date(Date.now() + 40 * 86_400_000);
    const swept = await pSvc.expireProvisional(pCfg, { now: later });
    check('one unconfirmed past the window is revoked', swept.expired.includes(staleRid));
    check('the confirmed record is NOT swept', !swept.expired.includes(pRid));

    const sweptList = await pStore.loadStatusList('NG');
    const staleRec = await pStore.findByResidentId(staleRid);
    check('the expired credential is actually revoked in the status list', !!staleRec && sweptList.isRevoked(staleRec.statusListIndex));
    check('the record survives so the person can re-enrol', !!staleRec);

    // A deployment that declares no window keeps its provisional records.
    const noPolicy: CountryConfig = parseCountryConfig({
      countryCode: 'NG',
      countryName: 'Nigeria',
      defaultSubnationalUnit: 'KT',
      foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
      residency: { minAssurance: 'verified', proofOfResidence: 'attestation', allowProvisional: true },
      credential: { issuerDid, issuerName: 'X', context: ['https://www.w3.org/ns/credentials/v2'] },
      subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
    });
    const unbounded = await pSvc.expireProvisional(noPolicy, { now: later });
    check('no declared window means nothing is expired', unbounded.expired.length === 0 && unbounded.checked === 0);
  }

  // --- The audit tail is anchored, so truncation is detectable --------------
  //
  // The hash chain proves nothing was edited, reordered or removed from the MIDDLE. It
  // proves nothing about the END: lopping off the last N events leaves a shorter chain that
  // verifies perfectly, and the most recent events are exactly the ones implicating whoever
  // just got write access. A signed checkpoint is what closes that.
  console.log('\nAudit anchoring (tail truncation):');
  {
    // A store whose contents the test can cut, standing in for an attacker with write access.
    class TruncatableStore implements AuditStore {
      events: AuditEvent[] = [];
      async append(e: AuditEvent) { this.events.push(e); }
      async replace(e: AuditEvent) {
        const i = this.events.findIndex((x) => x.seq === e.seq);
        if (i >= 0) this.events[i] = e;
      }
      async tail() {
        const last = this.events[this.events.length - 1];
        return last ? { seq: last.seq, hash: last.hash } : null;
      }
      async list() { return this.events.slice().reverse(); }
      async all() { return this.events.slice(); }
    }

    const aStore = new TruncatableStore();
    const cpStore = new InMemoryAuditCheckpointStore();
    const anchored = new AuditLog(aStore, cpStore, key.signer);
    const pub = [key.publicJwk];

    for (let i = 0; i < 6; i++) {
      await anchored.record({ action: 'residency.issue', actor: 'citizen', outcome: 'success' });
    }

    // No checkpoint yet: the chain is intact but the tail is unprotected, and that is
    // reported rather than shown as an unqualified pass.
    const beforeAnchor = await anchored.verifyChain({ publicJwks: pub });
    check('an unanchored chain verifies but says so', beforeAnchor.ok === true && beforeAnchor.anchored === false);
    check('and names the reason', beforeAnchor.anchorProblem === 'no-checkpoint');

    const cp = await anchored.checkpoint();
    check('a checkpoint commits to the head', !!cp && cp.seq === 5 && cp.count === 6);
    check('and is signed', !!cp && cp.signature.length > 0 && cp.kid === key.signer.kid);

    const anchoredOk = await anchored.verifyChain({ publicJwks: pub });
    check('an anchored, untouched chain verifies', anchoredOk.ok === true && anchoredOk.anchored === true);

    // Verifying without the key cannot trust the anchor, and must not pretend otherwise.
    const noKey = await anchored.verifyChain();
    check('without the public key the anchor is not trusted', noKey.anchored === false && noKey.anchorProblem === 'unsigned');

    // THE ATTACK: drop the last two events. Links stay perfect.
    aStore.events = aStore.events.slice(0, 4);
    const relinked = await anchored.verifyChain();
    check('the truncated chain still passes the LINK check alone', relinked.ok === true);

    const caught = await anchored.verifyChain({ publicJwks: pub });
    check('but the anchor catches the truncation', caught.ok === false);
    check('and reports where the chain now ends', caught.truncatedAfterSeq === 3);

    // An attacker who can delete events can usually write a checkpoint too. Signing is the
    // part they cannot forge, so a checkpoint under another key must not be believed.
    const forgedKey = await KeyStore.generate('not-the-issuer');
    const forgedStore = new InMemoryAuditCheckpointStore();
    const forged = new AuditLog(aStore, forgedStore, forgedKey.signer);
    await forged.checkpoint();
    const rejected = await forged.verifyChain({ publicJwks: pub });
    check('a checkpoint signed by an untrusted key is refused', rejected.ok === false && rejected.anchorProblem === 'untrusted');
    check('and the same checkpoint verifies under ITS own key', (await forged.verifyChain({ publicJwks: [forgedKey.publicJwk] })).ok === true);
  }

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
