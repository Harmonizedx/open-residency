// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * The residence rule: duration, intent, attester kinds, and residence modes.
 *
 * The property this file protects is that a jurisdiction's residence RULE -- how long, on
 * whose word, and for people without an ordinary dwelling -- is read from policy and applied
 * exactly, while a policy that declares none of it behaves precisely as before. Every new
 * parameter is optional; the default policy must evaluate identically to the day before these
 * existed, which the first block asserts against the unchanged outcomes.
 *
 * Second property: a refusal names what was actually wrong. "We could not tell how long" is
 * not "not long enough", and "your situation is not provided for" is not "your proof was weak".
 */
import {
  DEFAULT_RESIDENCE_POLICY,
  ResidenceEvidence,
  ResidencePolicy,
  evaluateResidence,
} from '../src/core/proofing/residence';
import { parseCountryConfig } from '../src/core/config/country-config';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';

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

const NOW = '2026-10-06T00:00:00.000Z';
const daysAgo = (n: number) => new Date(Date.parse(NOW) - n * 86_400_000).toISOString().slice(0, 10);

const base: ResidencePolicy = {
  required: true,
  targetLevel: 'RAL2',
  acceptedMethods: ['register_declared_residence', 'authority_attestation', 'document'],
  unitMatchRequired: true,
  acceptFoundationalResidence: false,
};
const attest = (extra: Partial<ResidenceEvidence> = {}): ResidenceEvidence => ({
  method: 'authority_attestation',
  adminUnit: 'KD',
  asOf: daysAgo(1),
  ...extra,
});

console.log('unchanged when the policy declares no rule');
{
  const before = evaluateResidence(base, [attest()], 'KD', NOW);
  check('an attestation still reaches RAL2 and satisfies', before.level === 'RAL2' && before.satisfied);
  check('mode is recorded as dwelling by default', before.mode === 'dwelling');
  check('no since, no intent, no attester recorded', before.since === undefined && before.intentDeclared === undefined && before.attesterType === undefined);
  const none = evaluateResidence(base, [], 'KD', NOW);
  check('no evidence still fails with the level reason', none.reason === 'PROOF_OF_RESIDENCE_BELOW_RAL2_GOT_RAL0');
  const def = evaluateResidence(DEFAULT_RESIDENCE_POLICY, [], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('a non-required default policy never refuses, even for an unadmitted mode', def.satisfied && def.reason === undefined);
  const stillDwelling = evaluateResidence(base, [attest()], 'KD', NOW, undefined, { intentToReside: true, since: daysAgo(5) });
  check('declarations are recorded but change nothing without a rule', stillDwelling.satisfied && stillDwelling.intentDeclared === true && stillDwelling.since === daysAgo(5));
}

console.log('duration rule');
{
  const p: ResidencePolicy = { ...base, minimumDurationDays: 182 };
  const young = evaluateResidence(p, [attest({ since: daysAgo(40) })], 'KD', NOW);
  check('evidence saying residence began 40 days ago fails a 182-day rule', !young.satisfied && young.reason === 'RESIDENCE_DURATION_BELOW_MINIMUM_182D');
  check('the level was still reached; the duration is a separate finding', young.level === 'RAL2');
  const old = evaluateResidence(p, [attest({ since: daysAgo(400) })], 'KD', NOW);
  check('evidence saying residence began 400 days ago passes', old.satisfied && old.since === daysAgo(400));
  const unknown = evaluateResidence(p, [attest()], 'KD', NOW);
  check('no start date anywhere is its own reason', unknown.reason === 'RESIDENCE_DURATION_UNKNOWN');
  const declaredOnly = evaluateResidence(p, [attest()], 'KD', NOW, undefined, { since: daysAgo(300) });
  check('the applicant\'s declared start is used when no evidence states one', declaredOnly.satisfied && declaredOnly.since === daysAgo(300));
  const evidenceWins = evaluateResidence(p, [attest({ since: daysAgo(30) })], 'KD', NOW, undefined, { since: daysAgo(900) });
  check('evidence outranks the declaration when both exist', !evidenceWins.satisfied && evidenceWins.since === daysAgo(30));
  const levelFirst = evaluateResidence(p, [], 'KD', NOW, undefined, { since: daysAgo(10) });
  check('with no evidence, the level reason comes before the duration reason', levelFirst.reason === 'PROOF_OF_RESIDENCE_BELOW_RAL2_GOT_RAL0');
  const notRequired = evaluateResidence({ ...p, required: false }, [attest({ since: daysAgo(3) })], 'KD', NOW);
  check('a duration rule on a non-required policy records and never refuses', notRequired.satisfied && notRequired.reason === undefined);
}

console.log('intent');
{
  const noIntent: ResidencePolicy = { ...base, minimumDurationDays: 182 };
  const r1 = evaluateResidence(noIntent, [attest({ since: daysAgo(10) })], 'KD', NOW, undefined, { intentToReside: true });
  check('declared intent counts for nothing unless the policy says it suffices', !r1.satisfied && r1.intentDeclared === true);
  const intentOk: ResidencePolicy = { ...noIntent, intentToResideSuffices: true };
  const r2 = evaluateResidence(intentOk, [attest({ since: daysAgo(10) })], 'KD', NOW, undefined, { intentToReside: true });
  check('with intentToResideSuffices, a declared intent satisfies the duration rule', r2.satisfied);
  const r3 = evaluateResidence(intentOk, [attest({ since: daysAgo(10) })], 'KD', NOW, undefined, { intentToReside: false });
  check('intent explicitly not declared does not satisfy it', !r3.satisfied && r3.reason === 'RESIDENCE_DURATION_BELOW_MINIMUM_182D');
  const r4 = evaluateResidence(intentOk, [], 'KD', NOW, undefined, { intentToReside: true });
  check('intent never substitutes for evidence of residence itself', !r4.satisfied && r4.reason === 'PROOF_OF_RESIDENCE_BELOW_RAL2_GOT_RAL0');
}

console.log('attester kinds');
{
  const p: ResidencePolicy = { ...base, attestation: { acceptedAttesterTypes: ['ward_officer', 'traditional_ruler'] } };
  const ok = evaluateResidence(p, [attest({ attesterType: 'ward_officer' })], 'KD', NOW);
  check('an attestation from a listed kind counts and the kind is recorded', ok.satisfied && ok.attesterType === 'ward_officer');
  const unlisted = evaluateResidence(p, [attest({ attesterType: 'employer' })], 'KD', NOW);
  check('an attestation from an unlisted kind counts for nothing', !unlisted.satisfied && unlisted.level === 'RAL0');
  const unstated = evaluateResidence(p, [attest()], 'KD', NOW);
  check('with a list in force, an attestation that does not state its kind counts for nothing', !unstated.satisfied);
  const anyKind = evaluateResidence(base, [attest({ attesterType: 'employer' })], 'KD', NOW);
  check('with no list, any kind counts', anyKind.satisfied);
  const doc = evaluateResidence(p, [{ method: 'document', adminUnit: 'KD', asOf: daysAgo(1) }], 'KD', NOW);
  check('the attester gate applies to attestations only; a document is untouched', doc.satisfied);
}

console.log('residence modes');
{
  const closed = evaluateResidence(base, [attest({ attesterType: 'camp_manager' })], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('no_fixed_abode is refused by name when the policy does not admit it', !closed.satisfied && closed.reason === 'RESIDENCE_MODE_NOT_ACCEPTED_no_fixed_abode');
  check('and no evidence was counted toward it', closed.level === 'RAL0');
  const refClosed = evaluateResidence(base, [attest()], 'KD', NOW, undefined, { mode: 'reference_address' });
  check('reference_address likewise', refClosed.reason === 'RESIDENCE_MODE_NOT_ACCEPTED_reference_address');

  const open: ResidencePolicy = {
    ...base,
    targetLevel: 'RAL1',
    attestation: { acceptedAttesterTypes: ['ward_officer'] },
    modes: {
      noFixedAbode: { allowed: true, acceptedAttesterTypes: ['camp_manager', 'ward_officer'], ceiling: 'RAL1' },
      referenceAddress: { allowed: true },
    },
  };
  const camp = evaluateResidence(open, [attest({ attesterType: 'camp_manager' })], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('admitted, a camp manager\'s attestation establishes no_fixed_abode', camp.satisfied && camp.mode === 'no_fixed_abode');
  check('at the mode\'s ceiling, not the method\'s', camp.level === 'RAL1');
  const campWrongKind = evaluateResidence(open, [attest({ attesterType: 'employer' })], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('the mode\'s own attester list governs, not the general one', !campWrongKind.satisfied);
  const campDoc = evaluateResidence(open, [{ method: 'document', adminUnit: 'KD', asOf: daysAgo(1) }], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('outside a dwelling, only an attestation is admissible; a document counts for nothing', !campDoc.satisfied && campDoc.level === 'RAL0');
  const refFallback = evaluateResidence(open, [attest({ attesterType: 'ward_officer' })], 'KD', NOW, undefined, { mode: 'reference_address' });
  check('a mode with no attester list falls back to the general list', refFallback.satisfied && refFallback.mode === 'reference_address');
  const refOther = evaluateResidence(open, [attest({ attesterType: 'landlord_or_host' })], 'KD', NOW, undefined, { mode: 'reference_address' });
  check('and refuses kinds the general list excludes', !refOther.satisfied);
  const otherUnit = evaluateResidence(open, [attest({ attesterType: 'camp_manager', adminUnit: 'KN' })], 'KD', NOW, undefined, { mode: 'no_fixed_abode' });
  check('the unit gate still applies in every mode', !otherUnit.satisfied);

  const addr: ResidencePolicy = { ...open, anchor: 'address' };
  const claimed = { lines: ['12 Ahmadu Bello Way'], adminUnit: 'KD' };
  const dwellingNoAddr = evaluateResidence(addr, [attest({ attesterType: 'ward_officer' })], 'KD', NOW, claimed, { mode: 'dwelling' });
  check('under address anchoring, dwelling evidence without the address still fails to match', !dwellingNoAddr.satisfied);
  const nfaAddr = evaluateResidence(addr, [attest({ attesterType: 'camp_manager' })], 'KD', NOW, claimed, { mode: 'no_fixed_abode' });
  check('under address anchoring, no_fixed_abode skips the address match by definition', nfaAddr.satisfied);
}

console.log('config schema');
{
  const cfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Example',
    defaultSubnationalUnit: 'KD',
    foundational: { provider: 'MOCK', assuranceOnSuccess: 'verified' },
    residency: {
      minAssurance: 'verified',
      residence: {
        required: true,
        targetLevel: 'RAL2',
        acceptedMethods: ['authority_attestation'],
        minimumDurationDays: 182,
        intentToResideSuffices: true,
        attestation: { acceptedAttesterTypes: ['ward_officer'] },
        modes: { noFixedAbode: { allowed: true, ceiling: 'RAL1' } },
      },
    },
    credential: { issuerDid: 'did:web:example.org', issuerName: 'Example', type: 'StateResidencyCredential', validityDays: 1, context: [] },
    subnationalUnits: [{ code: 'KD', name: 'Kaduna', level: 'state' }],
  });
  check('a full residence rule parses', cfg.residency.residence?.minimumDurationDays === 182 && cfg.residency.residence?.modes?.noFixedAbode?.allowed === true);
  let rejected = false;
  try {
    parseCountryConfig({
      countryCode: 'NG',
      countryName: 'Example',
      defaultSubnationalUnit: 'KD',
      foundational: { provider: 'MOCK', assuranceOnSuccess: 'verified' },
      residency: { minAssurance: 'verified', residence: { attestation: { acceptedAttesterTypes: ['village_elder'] } } },
      credential: { issuerDid: 'did:web:example.org', issuerName: 'Example', type: 'StateResidencyCredential', validityDays: 1, context: [] },
      subnationalUnits: [{ code: 'KD', name: 'Kaduna', level: 'state' }],
    });
  } catch {
    rejected = true;
  }
  check('an attester kind outside the vocabulary is refused at load', rejected);
}

async function endToEnd() {
  console.log('end to end: the record holds the rule inputs, the credential does not');
  const key = await KeyStore.generate('rules-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const cfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Example',
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
        acceptedMethods: ['authority_attestation'],
        unitMatchRequired: true,
        minimumDurationDays: 182,
        intentToResideSuffices: true,
        attestation: { acceptedAttesterTypes: ['ward_officer'] },
        modes: { noFixedAbode: { allowed: true, acceptedAttesterTypes: ['camp_manager'], ceiling: 'RAL1' } },
      },
    },
    credential: {
      issuerDid,
      issuerName: 'Example Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KD', name: 'Kaduna', parent: 'NG', level: 'state', iso3166_2: 'NG-KD' }],
  });
  const build = () =>
    new ResidencyService(new ProviderRegistry('rules-pepper'), new VcIssuer(key), new InMemoryStore(), () => 'https://example/status/ng.json');
  const NIN = '12345678950';

  const tooSoon = await build().issue(cfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'ward_officer', since: daysAgo(20) }],
  });
  check('the service refuses under the duration rule with the duration reason',
    tooSoon.status === 'rejected' && tooSoon.reason === 'RESIDENCE_DURATION_BELOW_MINIMUM_182D',
    tooSoon.status === 'rejected' ? tooSoon.reason : tooSoon.status);

  const withIntent = await build().issue(cfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    intentToReside: true,
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'ward_officer', since: daysAgo(20) }],
  });
  check('and issues when intent is declared and the policy counts it', withIntent.status === 'issued',
    withIntent.status === 'rejected' ? withIntent.reason : '');
  check('  the record carries since, attester and intent',
    withIntent.status === 'issued' && withIntent.record.residence.since === daysAgo(20)
      && withIntent.record.residence.attesterType === 'ward_officer' && withIntent.record.residence.intentDeclared === true);
  check('  and no mode, because it is an ordinary dwelling', withIntent.status === 'issued' && withIntent.record.residence.mode === undefined);

  const camp = await build().issue(cfg, {
    countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    residenceMode: 'no_fixed_abode',
    residenceSince: daysAgo(400),
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD', attesterType: 'camp_manager' }],
  });
  check('a person with no fixed abode is issued on a camp manager\'s word', camp.status === 'issued',
    camp.status === 'rejected' ? camp.reason : '');
  check('  the record says so', camp.status === 'issued' && camp.record.residence.mode === 'no_fixed_abode'
    && camp.record.residence.attesterType === 'camp_manager' && camp.record.residence.since === daysAgo(400));
  if (camp.status === 'issued') {
    const payload = JSON.parse(Buffer.from(camp.credentialJwt.split('.')[1], 'base64url').toString('utf8'));
    const text = JSON.stringify(payload);
    const subject = payload.vc?.credentialSubject ?? payload.credentialSubject;
    check('  the credential carries the residence level and method', subject?.residence?.assuranceLevel === 'RAL1' && subject?.residence?.method === 'authority_attestation');
    check('  and nothing about how the person resides or who vouched',
      !text.includes('no_fixed_abode') && !text.includes('attesterType') && !text.includes('intentDeclared')
        && subject?.residence?.mode === undefined && subject?.residence?.since === undefined, text.slice(0, 200));
  }
}

endToEnd()
  .then(() => {
    console.log(`\n${pass} passed, ${fail} failed`);
    process.exit(fail === 0 ? 0 : 1);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
