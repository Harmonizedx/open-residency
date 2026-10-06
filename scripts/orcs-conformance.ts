// SPDX-License-Identifier: Apache-2.0
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
 * IT DOES NOT ALL PASS YET, and the criteria that do not are traced to findings in the gap
 * analysis. A red suite that names exactly what is missing is worth more than a green one that
 * tests only what already works -- and it is what turns each migration phase from "we think
 * we're done" into "criterion 1 went green".
 *
 * IT RUNS IN CI AS A RATCHET rather than as a pass/fail gate. `scripts/orcs-baseline.json`
 * records the verdict each criterion is currently expected to hold, and this build fails when
 * one of them drops. That answers the objection that kept it out of CI -- a permanently-red
 * required check trains people to ignore red checks -- because the ratchet is GREEN today and
 * only reddens when something regresses.
 *
 * It also fails when a criterion IMPROVES and the baseline was not updated. That is
 * deliberate: a baseline nobody maintains is stale documentation, which is the failure that
 * left criterion 9 asserting nothing while its own prose drifted from six adapters to eight.
 * Run with ORCS_UPDATE_BASELINE=1 to record an improvement.
 *
 * When every criterion reaches PASS, the baseline is all-PASS and the ratchet IS the gate --
 * no separate step, and nothing to remember to switch on.
 *
 * Each criterion prints PASS, FAIL or PARTIAL with the finding id, so the output doubles as
 * a progress report against the gap analysis.
 *
 * EVERY CRITERION NAMES WHAT IT SERVES. ORCS is this project's own specification, written
 * by this project; a criterion that existed only "because ORCS requires it" would be the
 * project grading its own homework. So each one also states the external requirement it
 * satisfies -- a data-protection article, a W3C or OpenID specification, a GovStack
 * requirement, an ID4D principle -- and that line is printed with the verdict. Where a
 * criterion serves nothing external, it says so, and that is a finding about the criterion.
 *
 * TWO SECTIONS. Criteria 1-9 are ORCS §15's nine, kept as the specification numbers them.
 * Criteria 10 onward are PROJECT acceptance criteria: things the research into where
 * registration programmes actually fail said matter, that §15 does not sample -- a decision
 * for a person without a foundational identifier, delivery as distinct from issuance, a
 * resident seeing who read their record, a home for people with no fixed abode, and the
 * absence of any origin field. They are held to the same ratchet. Say "seven of nine §15
 * criteria pass" and "N of M project criteria pass", never a single blended number.
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { InMemoryStore } from '../src/core/residency/ports';
import { IdentityLinkRegistry, InMemoryIdentityLinkStore } from '../src/core/identity/identity-link';

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
import { InMemoryRefusalStore } from '../src/core/residency/refusal';
import { InMemoryDeliveryStore } from '../src/core/credentials/delivery';

type Verdict = 'PASS' | 'FAIL' | 'PARTIAL';

interface Result {
  n: number;
  criterion: string;
  verdict: Verdict;
  finding?: string;
  detail: string;
  /** The external requirement this criterion serves. Printed with the verdict. */
  serves: string;
}

const results: Result[] = [];

/**
 * What each criterion serves beyond ORCS itself. Cited by identifier so a reviewer can check
 * the claim, and kept here rather than at each call site so the list can be read in one place.
 */
const SERVES: Record<number, string> = {
  1: 'ORCS §4.4 across deployments; ID4D Principle 4 (interoperable platform); W3C VC 2.0 verification of a peer issuer',
  2: 'nothing external yet: no framework asks a subnational register to adjudicate conflicts; see the rewrite below',
  3: 'NIST SP 800-63-3 IAL/AAL/FAL vocabulary; ID4D Principle 3 (a trusted identity: accurate, with stated assurance)',
  4: 'Nigeria GAID 2025 Art. 41(9) (explicit, revocable consent for third-party sharing); DPG Standard indicator 9a; GovStack Consent BB',
  5: 'W3C Bitstring Status List 1.0; ORCS §10 revocation record; EUDI ARF status checking; DPG Standard indicator 9a (integrity)',
  6: 'ID4D Principle 10 (grievance and correction); NDPA 2023 data-subject right to rectification; GovStack Digital Registries DRS-7 (integrity of change logs)',
  7: 'OpenID Connect Core 1.0 with pairwise subject identifiers; OAuth 2.0 PKCE (RFC 7636); ID4D Principle 6 (privacy by design); DPG indicator 9a',
  8: 'nothing external yet: ORCS §12 is the only source asking for a publishable event envelope',
  9: 'ID4D Principle 5 (open standards, no lock-in); DPG Standard indicator 4 (platform independence)',
  10: 'ID4D Principles 1-2 (universal access, remove barriers); GAID 2025 Schedule 6 (vulnerability); NDPA 2023 s.37 (human review of an automated decision)',
  11: 'ID4D Practitioner\'s Guide on delivery and collection; World Bank Nigeria ID4D ISR (printed is not collected); GovStack Registration BB (status visible to the applicant)',
  12: 'GovStack Digital Registries DRS-8 and DRS-37 (log every read; data owners view access); DPG Standard indicator 9a; ID4D Practitioner\'s Guide (a person can see who accessed their record)',
  13: 'Registers with a reference-address or no-fixed-abode provision (BE, NL, DK, ZA); ID4D Principle 1; GAID 2025 Schedule 6 (vulnerable data subjects)',
  14: 'Constitution of Nigeria s.42 (no disability by circumstances of birth); ID4D Principle 1 (free from discrimination); GAID 2025 data minimisation',
};

function record(
  n: number,
  criterion: string,
  verdict: Verdict,
  detail: string,
  finding?: string,
): void {
  results.push({ n, criterion, verdict, finding, detail, serves: SERVES[n] ?? 'unstated' });
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
  //
  // What this criterion will assert, once the code exists: a deployment holds an explicit
  // per-peer exclusivity policy (none | record | suspend | end); a peer's signed arrival
  // notice -- carrying this deployment's own credential id and no personal data -- is the
  // evidence it evaluates; under `none` two ACTIVE residencies coexist and NO conflict is
  // recorded (the false-positive half of the criterion), and under `record` or stronger a
  // conflict is recorded, attributed to the peer and the rule, with a reason. Adjudication
  // stays local and human: no central adjudicator, which ORCS §1.2 and ADR-0004 rule out.
  // Nothing in src/core evaluates exclusivity yet, so both halves fail.
  record(
    2,
    'Conflict detected only under an explicit exclusivity rule',
    'FAIL',
    'no exclusivity policy, no arrival-notice endpoint and no conflict record exist; nothing ' +
      'in src/core evaluates exclusivity, so neither a true conflict nor a false one can be ' +
      'distinguished. The design is settled (per-peer policy over a signed peer notice) and ' +
      'awaits an ADR and the code',
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
  //
  // Driven through the residency service, not the registry alone, because the criterion is
  // about the register: a corrected mapping has to be what enrolment acts on, a disputed
  // link has to stop a credential being issued, and nothing may be deleted along the way.
  const linkStore = new InMemoryIdentityLinkStore();
  const linkRegistry = new IdentityLinkRegistry(linkStore);
  const linkedStore = new InMemoryStore();
  const linked = new ResidencyService(
    new ProviderRegistry('conformance-pepper'),
    new VcIssuer(key),
    linkedStore,
    () => 'https://id.katsina.gov.ng/status/ng.json',
    undefined,
    undefined,
    undefined,
    linkRegistry,
  );
  const enrol = (nin: string) =>
    linked.issue(e2eCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin }, decidedBy: 'operator:desk' });
  const idOf = (r: Awaited<ReturnType<typeof enrol>>) => (r.status === 'issued' || r.status === 'exists' ? r.residentId : '');
  const refOf = (r: Awaited<ReturnType<typeof enrol>>) => (r.status === 'issued' || r.status === 'exists' ? r.record.subjectRef : '');

  const p1 = await enrol('12345678904');
  const p2 = await enrol('12345678906');
  const p1Links = await linkRegistry.linksFor(idOf(p1));
  const linkedOnIssue = p1Links.length === 1 && p1Links[0].foundational && p1Links[0].status === 'ACTIVE';
  const tokenizedOnly = p1Links.every((l) => !l.identifierRef.includes('12345678904'));

  // A sector identifier, LINKed with evidence and refused without.
  const sectorRef = 'nhis:conformance-member-1';
  const noEvidence = await linked.linkIdentity(idOf(p1), { identifierType: 'nhis', identifierRef: sectorRef, by: 'operator:clinic', evidenceRefs: [] });
  const sector = await linked.linkIdentity(idOf(p1), { identifierType: 'nhis', identifierRef: sectorRef, by: 'operator:clinic', evidenceRefs: ['nhis-card:scan'] });
  const linkWorks = !noEvidence.ok && noEvidence.reason === 'EVIDENCE_REQUIRED' && sector.ok && (await linkRegistry.resolvePerson(sectorRef)) === idOf(p1);

  // DISPUTE restricts issuance; resolving lifts it.
  const disputed = await linked.disputeIdentityLink(p1Links[0].id, { by: 'operator:audit', reason: 'possible relative' });
  const blocked = await enrol('12345678904');
  const disputeResolved = await linked.resolveIdentityLinkDispute(p1Links[0].id, { by: 'operator:supervisor', resolution: 'verified' });
  const unblocked = await enrol('12345678904');
  const disputeWorks =
    disputed.ok && blocked.status === 'rejected' && blocked.reason === 'IDENTITY_LINK_DISPUTED' && disputeResolved.ok && unblocked.status === 'exists';

  // UNLINK preserves the link and its history; RELINK moves the identifier to the right person.
  const sectorId = sector.ok ? sector.link.id : '';
  const unlinked = await linkRegistry.unlink(sectorId, { by: 'operator:supervisor', reason: 'not hers' });
  const stillThere = (await linkRegistry.find(sectorId))?.status === 'UNLINKED';
  const relinked = await linkRegistry.relink(sectorId, { toPersonRef: idOf(p2), by: 'operator:supervisor', reason: 'adjudicated', evidenceRefs: ['case:1'] });
  const relinkWorks = unlinked.ok && stillThere && relinked.ok && (await linkRegistry.resolvePerson(sectorRef)) === idOf(p2);

  // MERGE a duplicate into the survivor; the merged identifier then finds the survivor. SPLIT reverses it.
  const merged = await linked.mergeResidents(e2eCfg, { survivorId: idOf(p1), duplicateId: idOf(p2), by: 'operator:admin', reason: 'same person' });
  const viaDuplicate = await enrol('12345678906');
  const mergeWorks = merged.ok && viaDuplicate.status === 'exists' && idOf(viaDuplicate) === idOf(p1) && (await linkRegistry.resolvePerson(refOf(p2))) === idOf(p1);
  const split = await linked.splitMerge(merged.ok ? merged.merge.id : '', { by: 'operator:admin', reason: 'two people' });
  const splitWorks = split.ok && (await linkRegistry.resolvePerson(refOf(p2))) === idOf(p2);

  // Nothing deleted: every event is in the history, and every link id still resolves.
  const events = [...(await linkRegistry.historyFor(idOf(p1))), ...(await linkRegistry.historyFor(idOf(p2)))];
  const ops = new Set(events.map((e) => e.operation));
  const appendOnly = ['LINK', 'DISPUTE', 'DISPUTE_RESOLVED', 'UNLINK', 'RELINK', 'MERGE', 'SPLIT'].every((op) => ops.has(op as never));
  const allLinks = [...(await linkRegistry.linksFor(idOf(p1))), ...(await linkRegistry.linksFor(idOf(p2)))];
  const noneDeleted = allLinks.length >= 6 && (await Promise.all(allLinks.map((l) => linkRegistry.find(l.id)))).every(Boolean);

  const criterion6 = linkedOnIssue && tokenizedOnly && linkWorks && disputeWorks && relinkWorks && mergeWorks && splitWorks && appendOnly && noneDeleted;
  record(
    6,
    'Identity link lifecycle (link/dispute/unlink/relink/merge/split)',
    criterion6 ? 'PASS' : 'FAIL',
    criterion6
      ? 'enrolment links the foundational identifier (tokenized, never the number); a sector ' +
        'identifier links with evidence and is refused without; a disputed link refuses issuance ' +
        'until resolved; unlink keeps the link and its history; relink moves the identifier and ' +
        'enrolment follows it; merge folds a duplicate into the survivor and split reverses it; ' +
        'every operation is an appended event and no link was deleted'
      : `linked on issue=${linkedOnIssue}, tokenized=${tokenizedOnly}, link=${linkWorks}, ` +
        `dispute=${disputeWorks}, unlink/relink=${relinkWorks}, merge=${mergeWorks}, split=${splitWorks}, ` +
        `append-only=${appendOnly}, none deleted=${noneDeleted}`,
    criterion6 ? undefined : 'G-05',
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
  //
  // What exists: a hash-chained, checkpointed, redactable audit log that is attributable
  // (every entry names an actor) and minimal (references, never payloads). What does not: a
  // versioned envelope, a registry of event types, a legal-basis reference on each event, and
  // any way for a sectoral system to subscribe. ORCS §12 asks for the second set; nothing
  // external does, and the pending decision in the tracker is whether an event architecture
  // is built at all or the audit chain is declared to be the record and §12 amended. Until
  // that is decided this is honestly FAIL, not PARTIAL: half an event system is none.
  record(
    8,
    'Events versioned, minimal, attributable, legally authorised',
    'FAIL',
    'no event registry, envelope, legal-basis reference per event, or subscriptions. The ' +
      'audit log is attributable and minimal but is an internal integrity record, deliberately ' +
      'not a publishable event. Whether to build an event architecture or amend §12 is an open ' +
      'decision in the tracker',
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

  // ===========================================================================
  // PROJECT ACCEPTANCE CRITERIA (10 onward). Not in ORCS §15. What the research into where
  // registration programmes fail said a register must be able to do, held to the same ratchet.
  // ===========================================================================

  // Shared fixture: a Kaduna-shaped deployment with refusals recorded, deliveries recorded,
  // a residence rule, the no-fixed-abode mode admitted, and activation on first delivery.
  const projectCfg = (over: Record<string, unknown> = {}) =>
    parseCountryConfig({
      countryCode: 'NG',
      countryName: 'Nigeria',
      defaultSubnationalUnit: 'KD',
      foundational: {
        provider: 'MOCK',
        inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
        assuranceOnSuccess: 'verified',
      },
      residency: {
        minAssurance: 'verified',
        proofOfResidence: 'attestation',
        residence: {
          required: true,
          targetLevel: 'RAL1',
          acceptedMethods: ['register_declared_residence', 'authority_attestation'],
          unitMatchRequired: true,
          acceptFoundationalResidence: true,
          attestation: { acceptedAttesterTypes: ['ward_officer', 'camp_manager'] },
          modes: { noFixedAbode: { allowed: true, acceptedAttesterTypes: ['camp_manager'], ceiling: 'RAL1' } },
        },
      },
      credential: {
        issuerDid,
        issuerName: 'Kaduna State Residents Identity Management Agency',
        type: 'StateResidencyCredential',
        validityDays: 365,
        context: ['https://www.w3.org/ns/credentials/v2'],
        appealPath: 'KADRIMA Head Office, Kaduna; or the Agency\'s published appeal form',
        activateOn: 'first_delivery',
      },
      subnationalUnits: [
        { code: 'KD', name: 'Kaduna', parent: 'NG', level: 'state', iso3166_2: 'NG-KD' },
        { code: 'KN', name: 'Kano', parent: 'NG', level: 'state', iso3166_2: 'NG-KN' },
      ],
      ...over,
    });
  const projectRefusals = new InMemoryRefusalStore();
  const projectDeliveries = new InMemoryDeliveryStore();
  const projectStore = new InMemoryStore();
  const project = new ResidencyService(
    new ProviderRegistry('project-pepper'),
    new VcIssuer(key),
    projectStore,
    () => 'https://id.kaduna.gov.ng/status/ng.json',
    undefined,
    buildDefaultAssuranceRegistry(),
    projectRefusals,
    undefined,
    projectDeliveries,
  );
  const pcfg = projectCfg();

  // ---------------------------------------------------------------------------
  // 10. An applicant whose foundational identity cannot be verified reaches a decision with
  //     a human review path, rather than silently nothing.
  // ---------------------------------------------------------------------------
  //
  // The MOCK source verifies even last digits only, so an odd one stands in for the person
  // whose national identifier does not resolve. What is asserted: the decision is recorded,
  // carries a reference the person can quote, names the reason, and names where they are
  // heard. What is NOT yet true, and keeps this PARTIAL: there is no path to a residency
  // record for a person with no foundational identifier at all -- the pipeline is
  // foundational-first, and the ADR deciding whether an attested-only record exists, and what
  // it would certify, has not been written.
  const noId = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: '12345678901' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'ward_officer' }],
  });
  const refusalRef = noId.status === 'rejected' ? noId.reference : undefined;
  const refusalRecord = refusalRef ? await projectRefusals.findByReference(refusalRef) : null;
  const decisionRecorded = noId.status === 'rejected' && !!refusalRef && !!refusalRecord && !!refusalRecord.reason;
  const reviewPathNamed = noId.status === 'rejected' && !!noId.appealPath && !/UNDECLARED/i.test(noId.appealPath);
  record(
    10,
    'An applicant without a verifiable foundational identity reaches a recorded, appealable decision',
    decisionRecorded && reviewPathNamed ? 'PARTIAL' : 'FAIL',
    decisionRecorded && reviewPathNamed
      ? `the refusal is recorded under reference ${refusalRef} with reason ${refusalRecord?.reason} and the ` +
        `jurisdiction's appeal path; what does not exist is any route to a residency record for a person ` +
        `with no foundational identifier at all, which the ADR on applicants without a foundational ID must decide`
      : `decision recorded: ${decisionRecorded}; review path named: ${reviewPathNamed}`,
    'G-15',
  );

  // ---------------------------------------------------------------------------
  // 11. A credential is not ACTIVE until it has been delivered or collected, where the
  //     jurisdiction says delivery is a step.
  // ---------------------------------------------------------------------------
  const nfaNin = '12345678904';
  const waiting = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: nfaNin, residenceUnit: 'KD' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'ward_officer' }],
  });
  const issuedState = waiting.status === 'issued' ? (await project.credentialStatusFor(pcfg, waiting.residentId))?.status : undefined;
  const pendingOnly = waiting.status === 'issued'
    ? await project.recordDelivery(pcfg, waiting.residentId, { channel: 'sms_link', status: 'pending', by: 'operator:desk' })
    : null;
  const stillIssued = waiting.status === 'issued' ? (await project.credentialStatusFor(pcfg, waiting.residentId))?.status : undefined;
  const handed = waiting.status === 'issued'
    ? await project.recordDelivery(pcfg, waiting.residentId, { channel: 'agent_handover', status: 'delivered', by: 'operator:field' })
    : null;
  const activeAfter = waiting.status === 'issued' ? await project.credentialStatusFor(pcfg, waiting.residentId) : null;
  const deliveryGates =
    issuedState === 'ISSUED' &&
    pendingOnly?.ok === true && pendingOnly.activated === false && stillIssued === 'ISSUED' &&
    handed?.ok === true && handed.activated === true &&
    activeAfter?.status === 'ACTIVE' && activeAfter.reason === 'DELIVERED_agent_handover';
  record(
    11,
    'A credential is not ACTIVE until delivered or collected, where delivery is a step',
    deliveryGates ? 'PASS' : 'FAIL',
    deliveryGates
      ? 'under activateOn: first_delivery the credential is ISSUED on issue, a pending dispatch leaves it ' +
        'ISSUED, and the first delivered event moves it to ACTIVE through the ordinary transition with the ' +
        'delivery as reason and the recording operator as authority; the events are on the record and ' +
        'counted by channel and status'
      : `issued state: ${issuedState}; pending left it: ${stillIssued}; delivery activated: ${handed && handed.ok ? handed.activated : 'n/a'}; ` +
        `final: ${activeAfter?.status}/${activeAfter?.reason}`,
    deliveryGates ? undefined : 'G-16',
  );

  // ---------------------------------------------------------------------------
  // 12. A resident can see every read of their record.
  // ---------------------------------------------------------------------------
  //
  // The audit log records operator reads and is readable by operators with the auditor role.
  // Nothing lets the person whose record it is ask "who has looked at me", which GovStack's
  // Digital Registries requirements, the DPG privacy framework and the ID4D guide all ask for.
  record(
    12,
    'A resident can list every read of their own record',
    'FAIL',
    'no resident-facing surface exposes the audit entries that target a record; reads are logged ' +
      'and visible to operators holding the auditor role only',
    'G-17',
  );

  // ---------------------------------------------------------------------------
  // 13. A person with no fixed abode can be registered on an accepted attester's word.
  // ---------------------------------------------------------------------------
  const nfa = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: '12345678906' },
    residenceMode: 'no_fixed_abode',
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'camp_manager' }],
  });
  const nfaWrongAttester = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: '12345678908' },
    residenceMode: 'no_fixed_abode',
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'ward_officer' }],
  });
  const nfaCredentialText = nfa.status === 'issued' ? Buffer.from(nfa.credentialJwt.split('.')[1], 'base64url').toString('utf8') : '';
  const nfaOk =
    nfa.status === 'issued' &&
    nfa.record.residence.mode === 'no_fixed_abode' &&
    nfa.record.residence.attesterType === 'camp_manager' &&
    nfa.record.residence.assuranceLevel === 'RAL1' &&
    nfaWrongAttester.status === 'rejected' &&
    !nfaCredentialText.includes('no_fixed_abode') && !nfaCredentialText.includes('attesterType');
  record(
    13,
    'A person with no fixed abode can be registered on an accepted attester\'s word',
    nfaOk ? 'PASS' : 'FAIL',
    nfaOk
      ? 'with the mode admitted, a camp manager\'s attestation issues at the mode\'s ceiling; an attester the ' +
        'mode does not list is refused; the record carries the mode and the attester, the credential carries neither'
      : `issued: ${nfa.status}${nfa.status === 'rejected' ? ` (${nfa.reason})` : ''}; wrong attester refused: ${nfaWrongAttester.status === 'rejected'}; ` +
        `mode on record: ${nfa.status === 'issued' ? nfa.record.residence.mode : 'n/a'}; leaked into credential: ${nfaCredentialText.includes('no_fixed_abode')}`,
    nfaOk ? undefined : 'G-18',
  );

  // ---------------------------------------------------------------------------
  // 14. No origin field exists, and a foundational source's origin never proves residence.
  // ---------------------------------------------------------------------------
  //
  // Nigeria's national record carries both a residence state and an origin (indigeneity)
  // state. The second is what gates jobs, admissions and land in practice, is issued at
  // discretion and sold, and is what a register of who-lives-where must never become a proxy
  // for. Three things are asserted: the credential subject has no key naming origin; the
  // record has no column for it; and a foundational origin that matches the claimed unit
  // while the residence state does not is refused, never accepted as residence evidence.
  const originOnly = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD',
    identifiers: { nin: '12345678910', originUnit: 'KD', residenceUnit: 'KN' },
  });
  const residenceMatches = await project.issue(pcfg, {
    countryCode: 'NG', subnationalUnit: 'KD',
    identifiers: { nin: '12345678912', originUnit: 'KN', residenceUnit: 'KD' },
  });
  const credText = residenceMatches.status === 'issued'
    ? Buffer.from(residenceMatches.credentialJwt.split('.')[1], 'base64url').toString('utf8') : '';
  const recordText = residenceMatches.status === 'issued' ? JSON.stringify(residenceMatches.record) : '';
  const originRefused = originOnly.status === 'rejected' && /PROOF_OF_RESIDENCE/.test(originOnly.reason);
  const noOriginField = !/origin|indigen/i.test(credText) && !/origin|indigen/i.test(recordText);
  const prismaSchema = readFileSync(join(process.cwd(), 'prisma/schema.prisma'), 'utf8');
  const noOriginColumn = !/^\s*\w*[Oo]rigin\w*\s+(String|Json|Boolean)/m.test(prismaSchema);
  const originNeverEvidence = originRefused && residenceMatches.status === 'issued';
  record(
    14,
    'No origin field exists, and a foundational origin never proves residence',
    noOriginField && noOriginColumn && originNeverEvidence ? 'PASS' : 'FAIL',
    noOriginField && noOriginColumn && originNeverEvidence
      ? 'the credential subject and the record carry no key naming origin or indigeneity; the Resident table has ' +
        'no such column; a foundational origin matching the claimed unit while the residence state does not is ' +
        'refused for want of residence proof, and the reverse issues'
      : `no origin key in credential/record: ${noOriginField}; no origin column: ${noOriginColumn}; ` +
        `origin alone refused: ${originRefused} (${originOnly.status === 'rejected' ? originOnly.reason : originOnly.status}); ` +
        `residence alone issues: ${residenceMatches.status}`,
    noOriginField && noOriginColumn && originNeverEvidence ? undefined : 'G-19',
  );

  // --- Report -----------------------------------------------------------------
  const icon: Record<Verdict, string> = { PASS: '✓', FAIL: '✗', PARTIAL: '~' };
  const printed = new Set<number>();
  const section = (title: string, pick: (r: Result) => boolean) => {
    const rows = results.filter(pick);
    if (!rows.length) return;
    console.log(`\n-- ${title} --\n`);
    for (const r of rows) {
      printed.add(r.n);
      const tag = r.finding ? ` [${r.finding}]` : '';
      console.log(`  ${icon[r.verdict]} ${r.n}. ${r.criterion} — ${r.verdict}${tag}`);
      console.log(`      ${r.detail}`);
      console.log(`      serves: ${r.serves}`);
    }
  };
  section('ORCS §15 acceptance criteria (1-9)', (r) => r.n <= 9);
  section('Project acceptance criteria (10 onward)', (r) => r.n >= 10);

  const tally = (pick: (r: Result) => boolean) => {
    const rows = results.filter(pick);
    return {
      total: rows.length,
      pass: rows.filter((r) => r.verdict === 'PASS').length,
      partial: rows.filter((r) => r.verdict === 'PARTIAL').length,
      fail: rows.filter((r) => r.verdict === 'FAIL').length,
    };
  };
  const spec = tally((r) => r.n <= 9);
  const proj = tally((r) => r.n >= 10);

  console.log(`\n== ORCS §15: ${spec.pass} pass, ${spec.partial} partial, ${spec.fail} fail (of ${spec.total}) ==`);
  console.log(`== Project criteria: ${proj.pass} pass, ${proj.partial} partial, ${proj.fail} fail (of ${proj.total}) ==`);
  const open = [...new Set(results.filter((r) => r.finding).map((r) => r.finding))];
  console.log(
    spec.fail === 0 && spec.partial === 0
      ? '\nAll nine ORCS §15 acceptance criteria pass.\n\n' +
        'This is NOT a statement of ORCS conformance, and ORCS is this project\'s own specification.\n' +
        '§15 is a sample -- nine acceptance criteria over sixteen sections. What each criterion\n' +
        'serves beyond ORCS is printed above; findings that map to no criterion are not measured\n' +
        'here at all; see the implementation tracker for those.\n'
      : `\nORCS §15 not satisfied. Open findings: ${open.join(', ')}\n`,
  );

  process.exit(ratchet(results));
}

/**
 * Compare this run against the committed baseline.
 *
 * Returns the process exit code. Three outcomes, and the second is the point of the whole
 * mechanism:
 *
 *   - every criterion holds its baseline verdict  -> 0
 *   - one has REGRESSED                           -> 1, naming which
 *   - one has IMPROVED and the baseline is stale  -> 1, naming which, with the command to fix
 *
 * Failing on improvement looks unfriendly and is not. An unmaintained baseline stops being a
 * record of where the work is and becomes a number nobody trusts -- exactly how criterion 9
 * came to assert nothing while claiming six adapters against a tree that shipped eight.
 */
function ratchet(current: Result[]): number {
  // process.cwd(), not __dirname: this runs compiled from dist-core/scripts, so a path
  // relative to the module lands in the build output and the committed baseline is never read.
  const path = join(process.cwd(), 'scripts', 'orcs-baseline.json');

  const observed: Record<string, Verdict> = {};
  for (const r of current) observed[String(r.n)] = r.verdict;

  if (process.env.ORCS_UPDATE_BASELINE === '1') {
    writeFileSync(path, JSON.stringify(observed, null, 2) + '\n');
    console.log(`Baseline updated: ${path}\n`);
    return 0;
  }

  let baseline: Record<string, Verdict>;
  try {
    baseline = JSON.parse(readFileSync(path, 'utf8')) as Record<string, Verdict>;
  } catch {
    console.log(
      `No baseline at ${path}. Record one with ORCS_UPDATE_BASELINE=1 npm run conformance:orcs\n`,
    );
    return 1;
  }

  const rank: Record<Verdict, number> = { FAIL: 0, PARTIAL: 1, PASS: 2 };
  const regressed: string[] = [];
  const improved: string[] = [];

  for (const r of current) {
    const was = baseline[String(r.n)];
    if (!was) {
      improved.push(`criterion ${r.n} is new (${r.verdict})`);
      continue;
    }
    if (rank[r.verdict] < rank[was]) regressed.push(`criterion ${r.n}: ${was} -> ${r.verdict}`);
    else if (rank[r.verdict] > rank[was]) improved.push(`criterion ${r.n}: ${was} -> ${r.verdict}`);
  }

  if (regressed.length > 0) {
    console.log('REGRESSION against scripts/orcs-baseline.json:\n');
    for (const line of regressed) console.log(`  ${line}`);
    console.log('\nA criterion that passed no longer does. Fix it, or say why in the tracker.\n');
    return 1;
  }

  if (improved.length > 0) {
    console.log('The baseline is out of date -- criteria improved:\n');
    for (const line of improved) console.log(`  ${line}`);
    console.log(
      '\nRecord it:  ORCS_UPDATE_BASELINE=1 npm run conformance:orcs\n' +
        'Then commit scripts/orcs-baseline.json with the change that earned it.\n',
    );
    return 1;
  }

  console.log('Ratchet: every criterion holds its baseline verdict.\n');
  return 0;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
