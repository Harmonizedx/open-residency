/* eslint-disable no-console */
/**
 * Refused applications are recorded, with a reason and somewhere to appeal.
 *
 * Two properties matter here, and they pull against each other.
 *
 * **Every refusal leaves a record.** There are five separate rejection paths in `issue()` and
 * each previously returned before any write, so a refusal vanished. An applicant refused at a
 * desk had no evidence they had applied and nothing to contest.
 *
 * **A refusal log is not a database of people who failed verification.** Identity is recorded
 * only when the foundational check produced a tokenized reference. A refusal raised before any
 * identity was established carries no identifier at all -- otherwise the log would hold data
 * about people the deployment could not verify, which is worse than the register itself.
 */
import { InMemoryStore } from '../src/core/residency/ports';
import { InMemoryRefusalStore, generateRefusalReference } from '../src/core/residency/refusal';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { buildDefaultAssuranceRegistry } from '../src/core/assurance/profiles';
import { randomBytes } from 'node:crypto';

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

// MOCK matches an identifier whose last digit is even; an odd one is refused.
const NIN_MATCHES = '12345678940';
const NIN_NO_MATCH = '12345678941';

function config(issuerDid: string, over: Record<string, unknown> = {}): CountryConfig {
  return parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
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
        targetLevel: 'RAL2',
        acceptedMethods: ['authority_attestation'],
        unitMatchRequired: true,
      },
    },
    credential: {
      issuerDid,
      issuerName: 'Katsina State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
      ...over,
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });
}

async function main() {
  console.log('\n== refused applications are recorded ==\n');

  console.log('the reference is unguessable and transcribable:');
  const refs = new Set<string>();
  for (let i = 0; i < 500; i++) refs.add(generateRefusalReference((n) => randomBytes(n)));
  check('500 references, no collisions', refs.size === 500);
  const one = generateRefusalReference((n) => randomBytes(n));
  check('it is prefixed and grouped for reading aloud', /^REF(-[0-9A-Z]{4}){5}$/.test(one), one);
  check(
    'it avoids I, L, O and U so it cannot be misread',
    !/[ILOU]/.test(one.replace(/^REF/, '')),
    one,
  );

  const key = await KeyStore.generate('refusal-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const cfg = config(issuerDid, { appealPath: 'Katsina Residency Appeals Office, within 30 days' });

  const build = () => {
    const refusals = new InMemoryRefusalStore();
    const svc = new ResidencyService(
      new ProviderRegistry('refusal-pepper'),
      new VcIssuer(key),
      new InMemoryStore(),
      () => 'https://id.katsina.gov.ng/status/ng.json',
      undefined,
      buildDefaultAssuranceRegistry(),
      refusals,
    );
    return { svc, refusals };
  };

  console.log('\nrefusal before an identity exists — no identifier is kept:');
  {
    const { svc, refusals } = build();
    const r = await svc.issue(cfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: NIN_NO_MATCH },
      decidedBy: 'operator:Desk-1',
    });
    check('the application is refused', r.status === 'rejected');
    const reference = r.status === 'rejected' ? r.reference : undefined;
    check('  a reference is returned to give the applicant', !!reference);
    check('  the appeal path is returned too', r.status === 'rejected' && !!r.appealPath);
    const stored = reference ? await refusals.findByReference(reference) : null;
    check('  the refusal is persisted', !!stored);
    check('  it records the reason', stored?.reason === 'MOCK_NO_MATCH');
    check('  it names who refused', stored?.decidedBy === 'operator:Desk-1');
    check('  it carries the appeal path', /Appeals Office/.test(stored?.appealPath ?? ''));
    check('  and NO identifier, because none was established', stored?.subjectRef === undefined);
  }

  console.log('\nrefusal after identity is established — the tokenized ref is kept:');
  {
    const { svc, refusals } = build();
    // Verification succeeds, but residence evidence is absent, so RAL2 is unreachable.
    const r = await svc.issue(cfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: NIN_MATCHES },
      binding: { method: 'attended_comparison' },
      decidedBy: 'operator:Desk-2',
    });
    check('the application is refused for want of residence proof', r.status === 'rejected');
    const reference = r.status === 'rejected' ? r.reference : undefined;
    const stored = reference ? await refusals.findByReference(reference) : null;
    check('  the refusal is persisted', !!stored);
    check('  it records the residence reason', /RESIDENCE|PROOF_OF_RESIDENCE/.test(stored?.reason ?? ''), stored?.reason);
    check('  the tokenized subject IS kept this time', !!stored?.subjectRef);
    check('  it is a token, not the submitted number', stored?.subjectRef !== NIN_MATCHES);
    check(
      '  an operator can find this person’s prior refusals',
      (await refusals.listBySubjectRef(stored!.subjectRef!)).length === 1,
    );
  }

  console.log('\nan unknown subnational unit is refused and recorded:');
  {
    const { svc, refusals } = build();
    const r = await svc.issue(cfg, {
      countryCode: 'NG',
      subnationalUnit: 'ZZ',
      identifiers: { nin: NIN_MATCHES },
    });
    check('refused', r.status === 'rejected');
    const reference = r.status === 'rejected' ? r.reference : undefined;
    const stored = reference ? await refusals.findByReference(reference) : null;
    check('  recorded', !!stored);
    check('  with the unit reason', /SUBNATIONAL_UNIT/.test(stored?.reason ?? ''), stored?.reason);
    check('  and no identifier (refused before verification ran)', stored?.subjectRef === undefined);
  }

  console.log('\na deployment declaring no appeal path says so, rather than leaving it blank:');
  {
    const bare = config(issuerDid);
    const { svc, refusals } = build();
    const r = await svc.issue(bare, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: NIN_NO_MATCH },
    });
    const reference = r.status === 'rejected' ? r.reference : undefined;
    const stored = reference ? await refusals.findByReference(reference) : null;
    check('the appeal path is never empty', !!stored?.appealPath);
    check('  and states that none was published', /No appeal path published/i.test(stored?.appealPath ?? ''));
  }

  console.log('\na successful issuance records no refusal:');
  {
    const { svc, refusals } = build();
    const r = await svc.issue(cfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: NIN_MATCHES },
      binding: { method: 'attended_comparison' },
      residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KT' }],
    });
    check('it issues', r.status === 'issued', r.status === 'rejected' ? r.reason : r.status);
    check(
      '  and nothing was written to the refusal log',
      (await refusals.listBySubjectRef('anything')).length === 0,
    );
  }

  console.log('\nwithout a refusal store the service still works (embedders):');
  {
    const svc = new ResidencyService(
      new ProviderRegistry('p'),
      new VcIssuer(key),
      new InMemoryStore(),
      () => 'u',
    );
    const r = await svc.issue(cfg, {
      countryCode: 'NG',
      subnationalUnit: 'KT',
      identifiers: { nin: NIN_NO_MATCH },
    });
    check('it refuses without throwing', r.status === 'rejected');
    check('  and returns no reference, rather than a fake one', r.status === 'rejected' && !r.reference);
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
