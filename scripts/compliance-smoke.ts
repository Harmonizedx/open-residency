// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * The data-protection kit: a record of processing and impact-assessment facts generated from
 * the configuration, and an append-only breach register.
 *
 * The property this file protects is honesty of the generated documents: they describe what
 * the configuration actually says, they are labelled as skeletons rather than filings, every
 * field the software cannot know is listed to complete, and nothing in them is a person's
 * identifier. For the breach register: the 72-hour clock runs from detection, not from entry;
 * a high-risk breach says subjects are told immediately; entries are never edited.
 */
import { parseCountryConfig } from '../src/core/config/country-config';
import { NEUTRAL_PROFILE, breachDeadlines, dpiaFacts, loadRegulatoryProfile, recordOfProcessing } from '../src/core/privacy/compliance';
import { InMemoryBreachStore, buildBreachRecord } from '../src/core/privacy/breach';

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

const base = {
  countryCode: 'NG',
  countryName: 'Nigeria',
  defaultSubnationalUnit: 'KD',
  foundational: { provider: 'MOCK', assuranceOnSuccess: 'verified' },
  residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
  credential: {
    issuerDid: 'did:web:example.org',
    issuerName: 'Kaduna State Residents Identity Management Agency',
    type: 'StateResidencyCredential',
    validityDays: 365,
    context: [],
    appealPath: 'KADRIMA Head Office',
  },
  subnationalUnits: [{ code: 'KD', name: 'Kaduna', level: 'state' }],
};

async function main() {
console.log('\n== data-protection kit ==\n');

console.log('regulatory profile is data, not code:');
const NG = loadRegulatoryProfile('config/privacy', 'NG');
check('the Nigerian profile ships and names its authority', NG !== undefined && /Data Protection Commission/.test(NG!.authority));
check('a country with no profile gets undefined, and the neutral profile cites no article', loadRegulatoryProfile('config/privacy', 'XX') === undefined && !/Art\./.test(JSON.stringify(NEUTRAL_PROFILE)));
check('the profile cites the registration-law trigger by article', NG!.dpiaTriggers.some((t) => /28\(3\)\(l\)/.test(t.ground)));

console.log('record of processing:');
{
  const cfg = parseCountryConfig({
    ...base,
    dataProtection: {
      controller: 'Kaduna State Government',
      processor: 'Kaduna State Residents Identity Management Agency',
      dpo: { name: 'The Agency’s accredited officer', email: 'dpo@example.gov.ng' },
      supervisoryRegistration: { authority: 'Nigeria Data Protection Commission', tier: 'extra_high' },
      legalBases: [
        { id: 'kd:residents-law-2021', kind: 'public_task', name: 'Residents registration', instrument: 'Kaduna State Residents Identity Management Agency Law, 2021', jurisdiction: 'Kaduna State', effectiveFrom: '2021-04-30' },
      ],
    },
    oidc: { relyingParties: [{ clientId: 'health-portal', name: 'State Health Insurance', sector: 'health', redirectUris: ['https://health.example/cb'], scopes: ['profile'] }] },
  });
  const ropa = recordOfProcessing(cfg, NG, '2026-10-06T00:00:00.000Z');
  check('is labelled a skeleton, not a filing', /not a filing/.test(ropa.status));
  check('names the controller, processor, officer and tier from config', ropa.controller === 'Kaduna State Government' && ropa.processor?.includes('Agency') === true && ropa.dataProtectionOfficer?.email === 'dpo@example.gov.ng' && ropa.supervisoryRegistration?.tier === 'extra_high');
  check('lists the declared legal basis', ropa.legalBases.some((b) => b.id === 'kd:residents-law-2021'));
  check('has one activity per processing purpose', ropa.activities.length >= 7 && ropa.activities.some((a) => a.id === 'resident-access-log') && ropa.activities.some((a) => a.id === 'delivery'));
  const enrol = ropa.activities.find((a) => a.id === 'enrolment-and-issuance')!;
  check('  enrolment cites the declared basis', enrol.legalBasisRefs.includes('kd:residents-law-2021'));
  check('  states what is deliberately not held, including origin', enrol.notHeld.some((n) => /origin|indigeneity/.test(n)) && enrol.notHeld.some((n) => /national identification number in clear/.test(n)));
  check('  says plainly that no retention is configured and quotes the profile on what follows', /no automatic expiry is configured/.test(enrol.retention) && /49\(3\)/.test(enrol.retention));
  check('  names the law and the authority from the profile', /Data Protection Act 2023/.test(ropa.law) && /Commission/.test(ropa.supervisoryAuthority));
  const sso = ropa.activities.find((a) => a.id === 'federated-sign-in')!;
  check('  names the relying party as a recipient', sso.recipients.some((r) => /State Health Insurance/.test(r) && /health-portal/.test(r)));
  check('lists what the deployment must complete, including hosting', ropa.toComplete.some((t) => /hosting/.test(t)));
  const text = JSON.stringify(ropa);
  check('contains no resident identifier shape', !/[A-Z]{2}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]/.test(text));

  const withRetention = recordOfProcessing(parseCountryConfig({ ...base, residency: { ...base.residency, retention: { residencyDays: 3650 } } }));
  check('a configured retention is stated as such', /expire 3650 days/.test(withRetention.activities[0].retention));
  const held = recordOfProcessing(parseCountryConfig({ ...base, residency: { ...base.residency, retention: { legalHold: true } } }));
  check('a legal hold is stated as such', /legal hold in force/.test(held.activities[0].retention));
}

console.log('\nimpact-assessment facts:');
{
  const plain = dpiaFacts(parseCountryConfig(base), NG, '2026-10-06T00:00:00.000Z');
  const neutral = dpiaFacts(parseCountryConfig(base), undefined, '2026-10-06T00:00:00.000Z');
  check('with no profile the triggers are neutral and uncited', neutral.triggers.length === 5 && !/Art\./.test(JSON.stringify(neutral.triggers)) && neutral.law === 'the applicable data-protection law');
  check('is labelled facts, not an assessment', /not an assessment/.test(plain.status));
  const law = plain.triggers.find((t) => /28\(3\)\(l\)/.test(t.ground))!;
  check('the registration-law trigger always applies', law.applies === true);
  check('no biometrics configured means that trigger does not apply, and says why', plain.triggers.find((t) => /biometrics/.test(t.ground))!.applies === false);
  check('vulnerable subjects applies regardless, with the reasoning', plain.triggers.find((t) => /vulnerable/.test(t.ground))!.applies === true);
  check('reports the residence anchor and self-service factors', plain.processing.residenceAnchor === 'unit' && plain.processing.selfServiceFactors.join(',') === 'presentation,ussd,otp');
  check('carries the human review path from config', plain.processing.humanReviewPath === 'KADRIMA Head Office');
  check('names ADR-0015 among mitigations', plain.mitigationsInSoftware.some((m) => /ADR-0015/.test(m)));

  const bio = dpiaFacts(parseCountryConfig({
    ...base,
    biometric: { provider: 'MOCK' },
    residency: { ...base.residency, residence: { required: true, targetLevel: 'RAL1', acceptedMethods: ['authority_attestation'], modes: { noFixedAbode: { allowed: true } } } },
  }), NG);
  check('a biometric provider turns the biometrics trigger on', bio.triggers.find((t) => /biometrics/.test(t.ground))!.applies === true);
  check('an admitted no-fixed-abode mode is reported under vulnerable subjects', bio.processing.vulnerableSubjectModesAdmitted.includes('no_fixed_abode') && /no_fixed_abode/.test(bio.triggers.find((t) => /vulnerable/.test(t.ground))!.because));
  check('special-category data names biometrics only when configured', bio.processing.specialCategoryData.some((s) => /biometric/.test(s)) && plain.processing.specialCategoryData[0] === 'none held by this software');

  const automated = dpiaFacts(parseCountryConfig({
    ...base,
    residency: { minAssurance: 'verified', applicantBinding: { required: false }, residence: { required: false, targetLevel: 'RAL0', acceptedMethods: ['register_declared_residence'] } },
  }), NG);
  check('a policy that permits a decision with nobody in the loop turns the automated-decision trigger on', automated.processing.automatedDecisionsPermitted === true && automated.triggers.find((t) => /s\.37/.test(t.ground))!.applies === true);
}

console.log('\nbreach register:');
{
  const d = breachDeadlines('2026-10-06T09:00:00.000Z', true, NG!.breachNotificationHours);
  check('the 72-hour deadline runs from detection', d.notifyAuthorityBy === '2026-10-09T09:00:00.000Z');
  check('high risk means subjects are told immediately', d.notifySubjects === 'immediately');
  check('low risk does not', breachDeadlines('2026-10-06T09:00:00.000Z', false).notifySubjects === 'not required unless risk rises');

  const store = new InMemoryBreachStore();
  const first = buildBreachRecord({
    countryCode: 'NG', detectedAt: '2026-10-06T09:00:00.000Z', recordedBy: 'operator:dpo',
    categories: ['confidentiality'], description: 'Operator laptop with cached exports lost', subjectsAffected: 1200, highRisk: true,
  }, 'b-1', '2026-10-06T15:00:00.000Z');
  await store.append(first);
  check('the record keeps detection and entry times apart', first.detectedAt !== first.recordedAt && first.notifyAuthorityBy === '2026-10-09T09:00:00.000Z');
  const amend = buildBreachRecord({
    countryCode: 'NG', detectedAt: '2026-10-06T09:00:00.000Z', recordedBy: 'operator:dpo',
    categories: ['confidentiality'], description: 'Laptop recovered; disk was encrypted; risk reassessed', highRisk: false, amends: 'b-1',
    authorityNotifiedAt: '2026-10-07T10:00:00.000Z',
  }, 'b-2', '2026-10-07T10:05:00.000Z');
  await store.append(amend);
  const all = await store.list('NG');
  check('entries are appended, never edited: both survive, oldest first', all.length === 2 && all[0].id === 'b-1' && all[1].amends === 'b-1');
  check('the amendment records when the authority was told', all[1].authorityNotifiedAt === '2026-10-07T10:00:00.000Z');
  check('another country sees nothing', (await store.list('XX')).length === 0);
  check('no field carries a subject identifier', !JSON.stringify(all).match(/[A-Z]{2}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]/));
}

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
