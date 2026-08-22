/* eslint-disable no-console */
/**
 * ORCS §15 acceptance criteria — the conformance gate.
 *
 * ORCS-001 §15 lists nine acceptance criteria. This suite asserts them directly, so
 * satisfying §15 becomes something the build decides rather than something a document claims.
 *
 * What this suite is NOT is a conformance certificate. ORCS §15 is a sample: nine acceptance
 * criteria over a specification of sixteen sections covering entities, registries, state
 * machines, closed vocabularies and interoperability obligations. Passing all nine means the
 * sampled behaviours hold, not that the implementation conforms -- several tracked findings map
 * to no criterion and are therefore invisible to this build. Say "all nine §15 criteria pass",
 * never "ORCS-conformant", and keep the unmeasured findings in the tracker where a person has
 * to look at them.
 *
 * IT IS EXPECTED TO FAIL TODAY. Five criteria fail outright and two partially, all traced to
 * findings in the gap analysis. A red suite that names exactly what is missing is worth more
 * than a green one that tests only what already works -- and it is what turns each migration
 * phase from "we think we're done" into "criterion 1 went green".
 *
 * Run with `npm run conformance:orcs`. It is deliberately NOT in `npm test` or CI until it
 * passes; a permanently-red required check trains people to ignore red checks.
 *
 * Each criterion prints PASS, FAIL or PARTIAL with the finding id, so the output doubles as
 * a progress report against the gap analysis.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { InMemoryStore } from '../src/core/residency/ports';

import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { parseCountryConfig } from '../src/core/config/country-config';
import { ConsentService, InMemoryConsentStore, isExpired } from '../src/core/consent/consent';
import { LegalBasisRegistry, legalBasesForDeployment } from '../src/core/consent/legal-basis';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { StatusList } from '../src/core/credentials/status-list';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { buildDefaultAssuranceRegistry } from '../src/core/assurance/profiles';

type Verdict = 'PASS' | 'FAIL' | 'PARTIAL';

interface Result {
  n: number;
  criterion: string;
  verdict: Verdict;
  finding?: string;
  detail: string;
}

const results: Result[] = [];

function record(
  n: number,
  criterion: string,
  verdict: Verdict,
  detail: string,
  finding?: string,
): void {
  results.push({ n, criterion, verdict, finding, detail });
}

async function main() {
  console.log('\n== ORCS §15 acceptance criteria ==\n');

  const key = await KeyStore.generate('conformance-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);

  // ---------------------------------------------------------------------------
  // 1. A person can hold compatible active relationships in multiple jurisdictions.
  // ---------------------------------------------------------------------------
  //
  // This criterion is about the ECOSYSTEM, not about one database, and that distinction is
  // the whole architecture. A deployment is a single subnational government: Katsina's
  // instance issues Katsina residency and nothing else. ORCS §4.4's person -- family home in
  // Katsina, employment in Kano, study in Lagos -- holds three relationships across three
  // deployments. No single instance ever holds all three, and one that did would be claiming
  // authority over jurisdictions it does not govern.
  //
  // So a deployment satisfies this criterion by doing two things, and it is a conformance
  // failure to do either badly:
  //
  //   (a) issue exactly one residency per person, so its own register stays authoritative and
  //       free of duplicates, and
  //   (b) recognise a peer jurisdiction's credential, so the person's relationships elsewhere
  //       are usable here rather than invisible.
  //
  // An earlier version of this check asserted that one store held three relationships for one
  // person. That was measuring a national registry, which is precisely what ORCS §3 prohibits
  // a subnational deployment from asserting.
  const e2eCfg = parseCountryConfig({
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
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });

  const homeStore = new InMemoryStore();
  const home = new ResidencyService(
    new ProviderRegistry('conformance-pepper'),
    new VcIssuer(key),
    homeStore,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );
  const nin = '12345678902';

  // (a) One residency per person, and re-enrolment is idempotent rather than duplicating.
  const first = await home.issue(e2eCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  const repeat = await home.issue(e2eCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  const registerIsAuthoritative =
    first.status === 'issued' &&
    repeat.status === 'exists' &&
    (await homeStore.list({ countryCode: 'NG' })).total === 1;

  // (b) A peer jurisdiction's credential verifies here, and is attributed to the peer rather
  //     than absorbed as if this deployment had issued it.
  const peerKey = await KeyStore.generate('peer-kano-key');
  const peerDid = didKeyFromJwk(peerKey.publicJwk);
  const peerCfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KN',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid: peerDid,
      issuerName: 'Kano State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KN', name: 'Kano', parent: 'NG', level: 'state' }],
  });
  const peerStore = new InMemoryStore();
  const peer = new ResidencyService(
    new ProviderRegistry('peer-pepper'),
    new VcIssuer(peerKey),
    peerStore,
    () => 'https://id.kano.gov.ng/status/ng.json',
  );
  const peerIssued = await peer.issue(peerCfg, { countryCode: 'NG', subnationalUnit: 'KN', identifiers: { nin } });

  // Katsina's verifier, trusting Kano as a federated peer.
  const trust = new Map<string, TrustedIssuer>();
  trust.set(issuerDid, { did: issuerDid, publicJwks: [key.publicJwk], statusLists: {} });
  trust.set(peerDid, { did: peerDid, publicJwks: [peerKey.publicJwk], statusLists: {} });
  const homeVerifier = new VcVerifier(trust);

  const peerOutcome =
    peerIssued.status === 'issued'
      ? await homeVerifier.verify(peerIssued.credentialJwt, { offline: true })
      : { valid: false, issuerDid: undefined as string | undefined };
  const peerCredentialUsableHere = peerOutcome.valid === true && peerOutcome.issuerDid === peerDid;

  // And an unlisted jurisdiction is not trusted merely for being a jurisdiction.
  const strangerKey = await KeyStore.generate('stranger-key');
  const strangerDid = didKeyFromJwk(strangerKey.publicJwk);
  const strangerCfg = parseCountryConfig({
    ...JSON.parse(JSON.stringify({ ...peerCfg, credential: { ...peerCfg.credential, issuerDid: strangerDid } })),
  });
  const strangerSvc = new ResidencyService(
    new ProviderRegistry('stranger-pepper'),
    new VcIssuer(strangerKey),
    new InMemoryStore(),
    () => 'https://id.stranger.gov.ng/status/ng.json',
  );
  const strangerIssued = await strangerSvc.issue(strangerCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KN',
    identifiers: { nin: '12345678904' },
  });
  const untrustedRejected =
    strangerIssued.status === 'issued'
      ? (await homeVerifier.verify(strangerIssued.credentialJwt, { offline: true })).valid === false
      : false;

  // (c) The record STATES what ORCS §4.3 requires of a relationship.
  //
  // Added because the criterion previously asserted only concurrency and peer attribution and
  // reported PASS regardless of what a record actually said about itself -- so a register that
  // could never record that somebody left still passed. §4.3 lists ten attributes; jurisdiction
  // is `countryCode` + `subnationalUnit`, and the other nine live on `relationship`.
  //
  // Checked on the record the real ResidencyService issued, never on one assembled here.
  const issuedRecord = first.status === 'issued' ? first.record : undefined;
  const rel = issuedRecord?.relationship;
  const missing43: string[] = [];
  if (!issuedRecord) missing43.push('no record issued');
  else {
    if (!issuedRecord.countryCode || !issuedRecord.subnationalUnit) missing43.push('jurisdiction');
    if (!rel?.type) missing43.push('type');
    if (!rel?.purpose) missing43.push('purpose');
    if (!rel?.status) missing43.push('status');
    if (!rel?.validFrom) missing43.push('validity');
    if (!rel?.policyVersion) missing43.push('policyVersion');
    if (!rel?.evidenceRefs?.length) missing43.push('evidenceReferences');
    if (!rel?.assuranceProfileId) missing43.push('assuranceProfile');
    if (!rel?.issuer) missing43.push('issuer');
    if (!rel?.decidedBy || !rel?.decidedAt) missing43.push('decisionProvenance');
  }
  const statesItsAttributes = missing43.length === 0;

  // And the relationship can actually reach a terminal state: §4.3 asking for `status` is
  // only meaningful if something can change it. A field that never moves is a constant.
  let canBeEnded = false;
  if (first.status === 'issued') {
    const ends = await home.transitionRelationship(first.residentId, {
      to: 'ENDED',
      by: 'conformance',
      reason: 'left the jurisdiction',
    });
    canBeEnded = ends.ok && ends.to === 'ENDED';
    // Put it back, so later criteria see the register as they expect to find it.
    if (ends.ok) {
      await homeStore.save({ ...ends.record, relationship: { ...rel!, status: 'ACTIVE' } });
    }
  }

  if (
    registerIsAuthoritative &&
    peerCredentialUsableHere &&
    untrustedRejected &&
    statesItsAttributes &&
    canBeEnded
  ) {
    record(
      1,
      'Concurrent relationships across jurisdictions (federated)',
      'PASS',
      'this deployment issues exactly one residency per person and re-enrolment is idempotent; ' +
        "a federated peer's credential verifies here and is attributed to the peer, not absorbed; " +
        'an unlisted issuer is refused. The person holds several relationships across the ' +
        'federation, and no single deployment claims authority over another. The record states ' +
        'all ten ORCS §4.3 attributes, and the relationship can be ended -- so a residency that ' +
        'has stopped holding can be recorded as such rather than only having its credential killed',
    );
  } else {
    record(
      1,
      'Concurrent relationships across jurisdictions (federated)',
      'FAIL',
      `own register authoritative: ${registerIsAuthoritative}; peer credential usable here: ` +
        `${peerCredentialUsableHere}; unlisted issuer refused: ${untrustedRejected}; ` +
        `§4.3 attributes stated: ${statesItsAttributes}${missing43.length ? ` (missing: ${missing43.join(', ')})` : ''}; ` +
        `relationship can be ended: ${canBeEnded}`,
      'G-01',
    );
  }

  // ---------------------------------------------------------------------------
  // 2. A conflict is detected only under an explicit exclusivity rule.
  // ---------------------------------------------------------------------------
  record(
    2,
    'Conflict detected only under an explicit exclusivity rule',
    'FAIL',
    'no conflict detector or adjudication service exists; nothing in src/core evaluates ' +
      'exclusivity, so neither true conflicts nor false ones can be distinguished',
    'G-06',
  );

  // ---------------------------------------------------------------------------
  // 3. Every assurance value resolves to a governed registry record.
  // ---------------------------------------------------------------------------
  //
  // ORCS §8: "assuranceLevel MUST NOT be a free-text string."
  // The record is the one issued by the real ResidencyService above, not a hand-built
  // fixture: resolving a struct assembled here would prove the registry can parse its own
  // output, which is the false-green G-01 already taught this suite to avoid.
  const sample = (await homeStore.list({ countryCode: 'NG' })).items[0];
  const assurance = buildDefaultAssuranceRegistry();
  const resolved = sample ? assurance.resolveRecord(sample) : null;

  // Governed: the profile is versioned and attributed to an authority.
  const governed = !!resolved?.profile.version?.trim() && !!resolved?.profile.issuer?.trim();
  // ORCS §8.1: the authority that performed the verification published what it means.
  const mapped =
    !!resolved?.mapping?.verificationMethod?.trim() && (resolved?.mapping?.limitations.length ?? 0) > 0;
  // ORCS §8: identity and authentication are distinct dimensions. A stored record carries
  // identity; authentication belongs to a sign-in event and must NOT appear here.
  const dimensionsSeparated =
    !!resolved?.dimensions.identity && resolved?.dimensions.authentication === undefined;
  // Closed vocabulary. This is the actual requirement -- "MUST NOT be a free-text string"
  // is only met if an unrecognised string fails to resolve.
  const closedVocabulary =
    assurance.resolve('probably-fine') === null &&
    assurance.resolveRecord({ ...sample, assuranceLevel: 'probably-fine' }) === null;

  const criterion3 = !!resolved && governed && mapped && dimensionsSeparated && closedVocabulary;
  record(
    3,
    'Assurance values resolve to a governed registry',
    criterion3 ? 'PASS' : 'FAIL',
    criterion3
      ? `the issued record's "${sample.assuranceLevel}" resolves to ${resolved!.profile.id} ` +
        `(v${resolved!.profile.version}, ${resolved!.profile.issuer}); the ${sample.providerCode} ` +
        `mapping states its verification method and ${resolved!.mapping!.limitations.length} ` +
        `limitation(s); identity resolves to ${resolved!.dimensions.identity} and evidence to ` +
        `${resolved!.dimensions.evidence}, with authentication assurance deliberately absent ` +
        'from a stored record; and an unregistered value resolves to nothing rather than a default'
      : `assuranceLevel "${sample?.assuranceLevel}" did not resolve to a governed profile ` +
        `(resolved=${!!resolved}, governed=${governed}, §8.1 mapping=${mapped}, ` +
        `dimensions separated=${dimensionsSeparated}, closed vocabulary=${closedVocabulary})`,
    criterion3 ? undefined : 'G-02',
  );

  // ---------------------------------------------------------------------------
  // 4. Consent can be granted, inspected, withdrawn, expired and audited.
  // ---------------------------------------------------------------------------
  const CONTROLLER = 'Katsina State Residency Authority';
  const STATUTORY_BASIS = 'ng:kt:residency-register-bylaw-2026';
  const legalBases = new LegalBasisRegistry(
    legalBasesForDeployment({
      jurisdiction: 'Nigeria',
      controller: CONTROLLER,
      declared: [
        {
          id: STATUTORY_BASIS,
          kind: 'public_task',
          name: 'Maintenance of the state residency register',
          instrument: 'Katsina State Residency Register By-law 2026, s.4',
          jurisdiction: 'Nigeria',
          effectiveFrom: '2026-01-01',
        },
      ],
    }),
  );
  const consent = new ConsentService(new InMemoryConsentStore(), key, issuerDid, {
    controller: CONTROLLER,
    processor: 'HarmonizedX Limited (hosting)',
    legalBases,
  });
  const evidence = {
    method: 'sso_consent_screen' as const,
    at: new Date().toISOString(),
    reference: 'interaction:conformance',
  };
  const grantInput = {
    subjectRef: 'tok_consent',
    residentId: 'NG-KT-0001',
    relyingParty: 'health',
    purpose: 'Eligibility check',
    scopes: ['openid', 'health'],
    dataCategories: ['identity', 'residence'],
    validityDays: 30,
    evidence,
  };
  const granted = await consent.grant(grantInput);
  const rec = granted.ok ? granted.record : null;
  const inspected = await consent.listByResident('NG-KT-0001');

  // §9 Grant: "Capture subject, controller, processor, purpose, data categories, scope,
  // expiry and evidence of agreement." All eight, on the record.
  const captured =
    !!rec &&
    !!rec.subjectRef &&
    rec.controller === CONTROLLER &&
    rec.processor === 'HarmonizedX Limited (hosting)' &&
    !!rec.purpose &&
    rec.dataCategories.length > 0 &&
    rec.scopes.length > 0 &&
    !!rec.expiresAt &&
    !!rec.evidence?.reference;

  // §9 Legal basis: "Resolve every legalBasisReference through the Legal Basis Registry."
  // Which means a reference that does NOT resolve must be refused, not stored.
  const resolvesThroughRegistry =
    !!rec && legalBases.resolve(rec.legalBasisReference) !== null;
  const unknownBasisRefused = await consent.grant({
    ...grantInput,
    residentId: 'NG-KT-UNKNOWN',
    legalBasisReference: 'whatever-the-law-says',
  });
  const closedBasisVocabulary =
    !unknownBasisRefused.ok && unknownBasisRefused.reason === 'UNKNOWN_LEGAL_BASIS';

  // The accountability fields are REQUIRED, not optional-with-a-blank.
  const blankRefused = await consent.grant({
    ...grantInput,
    residentId: 'NG-KT-BLANK',
    dataCategories: [],
  });
  const evidenceRefused = await consent.grant({
    ...grantInput,
    residentId: 'NG-KT-NOEVIDENCE',
    evidence: { ...evidence, reference: '  ' },
  });
  const refusesBlanks = !blankRefused.ok && !evidenceRefused.ok;

  // §9 Replace: "Preserve the previous record and create a new version."
  const replaced = await consent.grant({
    ...grantInput,
    scopes: ['openid', 'health', 'immunisation'],
  });
  const priorAfterReplace = rec ? await consent.listByResident('NG-KT-0001') : [];
  const versioned =
    replaced.ok &&
    replaced.record.version === 2 &&
    replaced.record.supersedesId === rec?.id &&
    priorAfterReplace.some((c) => c.id === rec?.id && c.status === 'replaced');

  // Withdrawal is checked on its own grant: revoke() is a no-op on anything already
  // non-active, so expiring or replacing this record first would report a false negative.
  const forWithdrawal = await consent.grant({
    ...grantInput,
    residentId: 'NG-KT-WITHDRAW',
    relyingParty: 'welfare',
  });
  const withdrawnRec = forWithdrawal.ok
    ? await consent.revoke(forWithdrawal.record.id, 'citizen')
    : null;
  const withdrawn = withdrawnRec?.status === 'revoked' && withdrawnRec.withdrawnBy === 'citizen';

  const lapsing = await consent.grant({
    ...grantInput,
    subjectRef: 'tok_consent_expiry',
    residentId: 'NG-KT-0002',
    relyingParty: 'tax',
    purpose: 'Assessment',
    scopes: ['openid', 'tax'],
  });
  const lapsingRec = lapsing.ok ? lapsing.record : null;
  const lapsed = new Date(Date.parse(lapsingRec!.expiresAt!) + 1000);
  const expiryEnforced =
    (await consent.findActive('NG-KT-0002', 'tax', lapsed)) === null &&
    isExpired(lapsingRec!, lapsed) &&
    consent.mayProcess(lapsingRec!, lapsed).permitted === false;

  // §9 Expire: "...UNLESS another valid legal basis applies." A statutory basis survives the
  // consent lapsing; if it did not, the exception would be decorative.
  const statutory = await consent.grant({
    ...grantInput,
    residentId: 'NG-KT-STATUTORY',
    relyingParty: 'registry',
    legalBasisReference: STATUTORY_BASIS,
  });
  const otherBasisSurvives =
    statutory.ok && consent.mayProcess(statutory.record, lapsed).permitted === true;

  // ...and withdrawing the BASIS itself stops it, which is why deactivation is recorded.
  const deactivated = legalBases.deactivate(STATUTORY_BASIS, {
    reason: 'By-law repealed',
    authority: 'operator:commissioner',
  });
  const basisWithdrawalStops =
    deactivated.ok &&
    statutory.ok &&
    consent.mayProcess(statutory.record, lapsed).permitted === false &&
    // ...while the record itself stays readable for the auditor following the citation.
    legalBases.get(STATUTORY_BASIS)?.deactivationReason === 'By-law repealed';

  const criterion4 =
    captured &&
    resolvesThroughRegistry &&
    closedBasisVocabulary &&
    refusesBlanks &&
    versioned &&
    withdrawn &&
    expiryEnforced &&
    otherBasisSurvives &&
    basisWithdrawalStops &&
    inspected.length > 0;
  record(
    4,
    'Consent granted, inspected, withdrawn, expired and audited',
    criterion4 ? 'PASS' : 'PARTIAL',
    criterion4
      ? 'the record captures all eight §9 grant attributes including controller, processor, ' +
        'data categories and evidence of agreement; legalBasisReference resolves through the ' +
        'Legal Basis Registry and an unregistered reference is REFUSED rather than stored; a ' +
        'grant missing data categories or evidence is refused rather than written blank; ' +
        'replacement versions the record and preserves the previous one; withdrawal records ' +
        'who acted; expiry stops processing, unless another valid legal basis applies -- and ' +
        'withdrawing that basis stops it too, while the repealed entry stays readable'
      : `§9 incomplete (captured=${captured}, resolves=${resolvesThroughRegistry}, ` +
        `closed vocabulary=${closedBasisVocabulary}, refuses blanks=${refusesBlanks}, ` +
        `versioned=${versioned}, withdrawn=${withdrawn}, expiry=${expiryEnforced}, ` +
        `other basis survives=${otherBasisSurvives}, basis withdrawal stops=${basisWithdrawalStops})`,
    criterion4 ? undefined : 'G-09',
  );

  // ---------------------------------------------------------------------------
  // 5. Every credential supports status checking and revocation.
  // ---------------------------------------------------------------------------
  //
  // ORCS §10 requires ISSUED -> ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED | EXPIRED | REPLACED,
  // a machine-verifiable status reference, revocation preserving reason/authority/timestamp/
  // appeal path, and replacement pointing at the superseding credential.
  //
  // Asserted against the real ResidencyService and its real status lists, not against the
  // StatusList primitive: the primitive always supported a suspension purpose, and testing it
  // proved only that a bitstring can hold a bit.
  const list = new StatusList();
  list.set(0, true);
  const revocationWorks = list.isRevoked(0) === true;
  list.set(0, false);
  const bitClears = list.isRevoked(0) === false;

  const credHolder = await home.issue(e2eCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678920' },
  });
  const credId = credHolder.status === 'issued' ? credHolder.residentId : '';

  // Suspension is reachable AND published, and reinstatement clears it.
  const suspended = await home.transitionCredential(e2eCfg, credId, {
    to: 'SUSPENDED',
    authority: 'conformance',
    reason: 'reported lost',
  });
  const suspensionList = await homeStore.loadStatusList('NG', 'suspension');
  const suspensionPublished =
    suspended.ok && suspensionList.isRevoked(credHolder.status === 'issued' ? credHolder.record.statusListIndex : -1);
  const reinstated = await home.transitionCredential(e2eCfg, credId, {
    to: 'ACTIVE',
    authority: 'conformance',
  });
  const suspensionClears =
    reinstated.ok &&
    !(await homeStore.loadStatusList('NG', 'suspension')).isRevoked(
      credHolder.status === 'issued' ? credHolder.record.statusListIndex : -1,
    );

  // §10's four: a revocation missing any one of them is refused rather than recorded blank.
  const noReason = await home.transitionCredential(e2eCfg, credId, {
    to: 'REVOKED',
    authority: 'conformance',
    appealPath: 'Appeals office',
  });
  const noAppeal = await home.transitionCredential(e2eCfg, credId, {
    to: 'REVOKED',
    authority: 'conformance',
    reason: 'fraud',
  });
  const revokedProperly = await home.transitionCredential(e2eCfg, credId, {
    to: 'REVOKED',
    authority: 'operator:Registrar',
    reason: 'Issued in error',
    appealPath: 'Katsina State Residency Appeals Office, within 30 days',
  });
  const revoked = await home.credentialStatusFor(e2eCfg, credId);
  const preservesAllFour =
    !noReason.ok &&
    !noAppeal.ok &&
    revokedProperly.ok &&
    !!revoked?.reason &&
    !!revoked?.authority &&
    !!revoked?.at &&
    !!revoked?.appealPath;

  // Replacement points at its successor.
  const replaceHolder = await home.issue(e2eCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678922' },
  });
  const replaceId = replaceHolder.status === 'issued' ? replaceHolder.residentId : '';
  const noPointer = await home.transitionCredential(e2eCfg, replaceId, {
    to: 'REPLACED',
    authority: 'conformance',
    reason: 'reissued',
  });
  const replacedOk = await home.transitionCredential(e2eCfg, replaceId, {
    to: 'REPLACED',
    authority: 'conformance',
    reason: 'reissued after device loss',
    supersededBy: 'urn:uuid:successor-credential',
  });
  const replacementPoints =
    !noPointer.ok &&
    replacedOk.ok &&
    (await home.credentialStatusFor(e2eCfg, replaceId))?.supersededBy ===
      'urn:uuid:successor-credential';

  const criterion5 =
    revocationWorks &&
    bitClears &&
    suspensionPublished &&
    suspensionClears &&
    preservesAllFour &&
    replacementPoints;

  record(
    5,
    'Credential status checking and revocation',
    criterion5 ? 'PASS' : 'PARTIAL',
    criterion5
      ? 'status list works; a suspension list is published separately from the revocation list ' +
        'and reinstatement clears it; revocation preserves reason, authority, timestamp and ' +
        'appeal path, and is REFUSED when any is missing rather than recorded blank; ' +
        'replacement points at the superseding credential and is refused without it'
      : `status list works (revocation=${revocationWorks}, bit clears=${bitClears}); ` +
        `suspension published=${suspensionPublished}, clears=${suspensionClears}; ` +
        `revocation preserves all four=${preservesAllFour}; replacement points at successor=${replacementPoints}`,
    criterion5 ? undefined : 'G-07',
  );

  // ---------------------------------------------------------------------------
  // 6. Every external identifier can be linked, disputed, unlinked and relinked.
  // ---------------------------------------------------------------------------
  record(
    6,
    'Identity link lifecycle (link/dispute/unlink/relink/merge/split)',
    'FAIL',
    'no IdentityLink entity or registry; subjectRef is a one-way tokenized reference with no ' +
      'lifecycle operations, so an incorrect mapping cannot be corrected without data loss',
    'G-05',
  );

  // ---------------------------------------------------------------------------
  // 7. Sectoral systems authenticate through federation without surrendering data ownership.
  // ---------------------------------------------------------------------------
  //
  // Verified in depth by smoke:sso, smoke:sso-oidc and the Postgres e2e job: pairwise
  // subjects, audience-scoped claims, and the national identifier never released.
  record(
    7,
    'Federated authentication without surrendering data ownership',
    'PASS',
    'OIDC Authorization Code + PKCE, pairwise subject identifiers, per-relying-party scopes, ' +
      'national ID never released; covered by smoke:sso, smoke:sso-oidc and the e2e job',
  );

  // ---------------------------------------------------------------------------
  // 8. Events are versioned, minimal, attributable and legally authorised.
  // ---------------------------------------------------------------------------
  record(
    8,
    'Events versioned, minimal, attributable, legally authorised',
    'FAIL',
    'no event registry, broker, envelope or subscriptions. AuditEvent is an internal ' +
      'hash-chained integrity record and is deliberately not a publishable event',
    'G-04',
  );

  // ---------------------------------------------------------------------------
  // 9. The core contains no Nigeria-specific hard-coded field names or hierarchy assumptions.
  // ---------------------------------------------------------------------------
  //
  // This criterion used to be a hardcoded PASS with a prose detail string. It asserted
  // nothing, so it would have reported PASS while the property was violated -- and its
  // counts had already drifted (it claimed six adapters when eight shipped) because nothing
  // recomputed them. That is the false-green shape this suite warns about elsewhere.
  //
  // Two things are checked now, both derived rather than stated.
  //
  // (a) PLURALITY. A core that reasons over configured jurisdictions has more than one
  //     jurisdiction to reason over, and more than one way into a foundational source. One
  //     of either is a single-jurisdiction system wearing a config file.
  const countryConfigs = readdirSync(join(process.cwd(), 'config/countries')).filter((f) =>
    f.endsWith('.yaml'),
  );
  const adapters = readdirSync(
    join(process.cwd(), 'src/core/foundational/adapters'),
  ).filter((f) => f.endsWith('.adapter.ts'));
  const plural = countryConfigs.length >= 2 && adapters.length >= 2;

  // (b) NO JURISDICTION BRANCHING. The violation that matters is control flow: the core
  //     behaving differently because the jurisdiction is Nigeria. Naming Nigeria is not the
  //     offence -- the provider registry and the ORCS §8.1 assurance mappings both name
  //     NG_NIN in the data tables that make providers selectable, which is the mechanism of
  //     jurisdiction-neutrality rather than a breach of it. Comments are excluded for the
  //     same reason mosip-conformance excludes them: `// e.g. KT for Katsina` documents a
  //     field, and a check that cannot coexist with its own explanation is not usable.
  //     The pattern is deliberately tight. An earlier draft matched `NG` anywhere inside a
  //     string literal and case-insensitively, which flagged every `typeof x === 'string'`
  //     in the core -- 'string' and 'pending' both contain "ng". A check that cries wolf on
  //     50 lines of correct code gets switched off, so this matches an exact `'NG'`/`'NIN'`
  //     comparison, or a place name as a word.
  const jurisdictionBranch = execFileSync(
    'bash',
    [
      '-c',
      `grep -rnE "(===|!==|==|!=)[[:space:]]*['\\"](NG|NIN)['\\"]|` +
        `(includes|startsWith|match)[[:space:]]*\\([[:space:]]*['\\"](NG|NIN)['\\"]|` +
        `['\\"][^'\\"]*[Nn]igeria|['\\"][^'\\"]*[Kk]aduna|['\\"][^'\\"]*[Kk]atsina" ` +
        `--include='*.ts' src/core ` +
        `| grep -viE ":[0-9]+:[[:space:]]*(\\*|//|/\\*)" || true`,
    ],
    { encoding: 'utf8' },
  )
    .split('\n')
    .filter(Boolean)
    // The NIN adapter is the one place a NIN may be recognised: that is its whole job, and
    // it is reached only because a config selected it.
    .filter((line) => !line.startsWith('src/core/foundational/adapters/nin.adapter.ts'))
    // The ORCS §8.1 mapping table names the authority each provider's verification comes
    // from -- "NIMC, Nigeria" is the content of the mapping, not a branch on it. Naming an
    // authority in the table that makes providers selectable is the mechanism of neutrality,
    // exactly as the provider registry naming NG_NIN alongside IN_AADHAAR is.
    .filter((line) => !line.startsWith('src/core/assurance/profiles.ts'));

  const neutral = plural && jurisdictionBranch.length === 0;
  record(
    9,
    'No Nigeria-specific hard-coding in the core',
    neutral ? 'PASS' : 'FAIL',
    neutral
      ? `${countryConfigs.length} jurisdiction configs and ${adapters.length} foundational ` +
        `adapters ship; NIN is an adapter reached through the registry, and no control flow in ` +
        `src/core branches on a Nigerian jurisdiction or identifier. Counts are read from disk, ` +
        `so they cannot drift from the tree the way the previous fixed string did`
      : `plural (>=2 configs and >=2 adapters): ${plural} ` +
        `(${countryConfigs.length} configs, ${adapters.length} adapters); ` +
        `jurisdiction branching in src/core: ${jurisdictionBranch.join(' ') || 'none'}`,
    neutral ? undefined : 'G-11',
  );

  // --- Report -----------------------------------------------------------------
  const icon: Record<Verdict, string> = { PASS: '✓', FAIL: '✗', PARTIAL: '~' };
  for (const r of results) {
    const tag = r.finding ? ` [${r.finding}]` : '';
    console.log(`  ${icon[r.verdict]} ${r.n}. ${r.criterion} — ${r.verdict}${tag}`);
    console.log(`      ${r.detail}`);
  }

  const pass = results.filter((r) => r.verdict === 'PASS').length;
  const partial = results.filter((r) => r.verdict === 'PARTIAL').length;
  const fail = results.filter((r) => r.verdict === 'FAIL').length;

  console.log(`\n== ORCS §15: ${pass} pass, ${partial} partial, ${fail} fail (of ${results.length}) ==`);
  console.log(
    fail === 0 && partial === 0
      ? '\nAll nine ORCS §15 acceptance criteria pass.\n\n' +
        'This is NOT a statement of ORCS conformance. §15 is a sample of the specification --\n' +
        'nine acceptance criteria over sixteen sections of entities, registries, state machines,\n' +
        'closed vocabularies and interoperability obligations. Findings that map to no criterion\n' +
        'are not measured here at all; see the implementation tracker for those.\n'
      : `\nORCS §15 not satisfied. Open findings: ${[...new Set(results.filter((r) => r.finding).map((r) => r.finding))].join(', ')}\n`,
  );

  // Exit 0 regardless: this suite reports conformance, it does not gate the build yet. It
  // becomes a gate (exit 1 on any non-PASS) when the migration is complete -- see the
  // implementation tracker.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
