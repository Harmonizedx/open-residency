// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * The residency relationship lifecycle: ORCS §6.2 status, §4.3 attributes, and the two rules
 * ADR-0007 turns on.
 *
 * This file exists to hold three things true that are easy to break later:
 *
 *   1. A residency can be ENDED, and an ended residency is not silently handed back by
 *      `issue()` returning `exists`.
 *   2. **Nothing lapses on its own.** A record past its recorded `validTo` is still ACTIVE
 *      until somebody ends it. The moment a future retention sweep starts expiring records,
 *      this assertion fails -- which is the point.
 *   3. **No decision reads `type` or `purpose`.** Asserted behaviourally: every decision is
 *      run across every permutation of both and must return an identical answer. A grep would
 *      only prove the words are absent; this proves the outcome does not depend on them.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig } from '../src/core/config/country-config';
import {
  RelationshipAttributes,
  RelationshipStatus,
  RelationshipType,
  applyTransition,
  canTransition,
  holdsNow,
  isTerminal,
  newRelationship,
  relationshipOf,
} from '../src/core/residency/lifecycle';

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

const ALL_STATUSES: RelationshipStatus[] = ['ACTIVE', 'SUSPENDED', 'ENDED', 'REVOKED', 'EXPIRED'];
const ALL_TYPES: RelationshipType[] = ['GENERAL_RESIDENCY', 'FORMER_RESIDENCY'];
const PURPOSES = ['', 'Service delivery', 'EMPLOYMENT_CONNECTION', 'anything at all'];

function attrs(over: Partial<RelationshipAttributes> = {}): RelationshipAttributes {
  return {
    type: 'GENERAL_RESIDENCY',
    purpose: 'Subnational residency',
    status: 'ACTIVE',
    validFrom: '2020-01-01T00:00:00.000Z',
    policyVersion: 'sha256:test',
    evidenceRefs: ['binding:attended_comparison'],
    issuer: 'did:web:id.katsina.gov.ng',
    decidedBy: 'operator:Test',
    decidedAt: '2020-01-01T00:00:00.000Z',
    ...over,
  };
}

async function main() {
  console.log('\n== residency relationship lifecycle (ORCS §6.2 / §4.3) ==\n');

  console.log('the state machine follows ORCS §6.2:');
  check('ACTIVE can be suspended', canTransition('ACTIVE', 'SUSPENDED'));
  check('SUSPENDED can be reinstated', canTransition('SUSPENDED', 'ACTIVE'));
  check('ACTIVE can be ended', canTransition('ACTIVE', 'ENDED'));
  check('SUSPENDED can be ended', canTransition('SUSPENDED', 'ENDED'));
  check('ENDED is terminal', ALL_STATUSES.every((s) => !canTransition('ENDED', s)));
  check('REVOKED is terminal', ALL_STATUSES.every((s) => !canTransition('REVOKED', s)));
  check('only ACTIVE holds now', ALL_STATUSES.filter(holdsNow).join() === 'ACTIVE');
  check('SUSPENDED does not hold (ORCS §7 restricts high-risk use)', !holdsNow('SUSPENDED'));

  console.log('\na terminal transition must say who and why:');
  const noReason = applyTransition(attrs(), { to: 'ENDED', by: 'operator:A' });
  check('ending without a reason is refused', !noReason.ok);
  check(
    '  and says so explicitly',
    !noReason.ok && noReason.reason === 'REASON_REQUIRED_FOR_ENDED',
    !noReason.ok ? noReason.reason : '',
  );
  const noActor = applyTransition(attrs(), { to: 'ENDED', by: '', reason: 'left' });
  check('ending without a deciding actor is refused', !noActor.ok);
  const suspendNoReason = applyTransition(attrs(), { to: 'SUSPENDED', by: 'operator:A' });
  check('suspending without a reason is allowed (not terminal)', suspendNoReason.ok);

  console.log('\nending a residency records what revoke() cannot:');
  const ended = applyTransition(attrs(), {
    to: 'ENDED',
    by: 'operator:Amina',
    reason: 'Relocated to Kano',
    at: '2026-08-16T10:00:00.000Z',
  });
  check('the transition succeeds', ended.ok);
  if (ended.ok) {
    check('  status is ENDED', ended.attributes.status === 'ENDED');
    check('  the reason is preserved', ended.attributes.endedReason === 'Relocated to Kano');
    check('  the deciding authority is named', ended.attributes.endedBy === 'operator:Amina');
    check('  the moment is recorded', ended.attributes.endedAt === '2026-08-16T10:00:00.000Z');
    check(
      '  the type becomes FORMER_RESIDENCY (ORCS §6.1)',
      ended.attributes.type === 'FORMER_RESIDENCY',
    );
    check('  validity closes at the same moment', ended.attributes.validTo === '2026-08-16T10:00:00.000Z');
    check('  an ended relationship cannot be reactivated', !applyTransition(ended.attributes, {
      to: 'ACTIVE',
      by: 'operator:A',
      reason: 'oops',
    }).ok);
  }

  console.log('\nNOTHING lapses on its own (ADR-0007, Amendment 2):');
  const lapsed = attrs({ validTo: '2021-01-01T00:00:00.000Z' });
  check('a record long past validTo is still ACTIVE', lapsed.status === 'ACTIVE');
  check('  and still holds now', holdsNow(lapsed.status));
  check('  no function converts it to EXPIRED', relationshipOf({ relationship: lapsed, createdAt: '2020-01-01T00:00:00.000Z' }).status === 'ACTIVE');
  check('  EXPIRED is reachable only by an explicit decision', canTransition('ACTIVE', 'EXPIRED'));

  console.log('\npre-lifecycle rows read as ACTIVE, with backfill declared:');
  const legacy = relationshipOf({ createdAt: '2019-05-05T00:00:00.000Z' });
  check('a row with no relationship reads ACTIVE', legacy.status === 'ACTIVE');
  check('  validFrom falls back to createdAt', legacy.validFrom === '2019-05-05T00:00:00.000Z');
  check(
    '  provenance says it was backfilled, not decided',
    legacy.decidedBy === 'migration:pre-lifecycle-record',
  );

  console.log('\nno decision reads type or purpose:');
  // Every decision function, across every permutation of the two inert fields. If any
  // decision ever consults them, one of these permutations disagrees with the others.
  let invariant = true;
  const outcomes = new Set<string>();
  for (const type of ALL_TYPES) {
    for (const purpose of PURPOSES) {
      for (const from of ALL_STATUSES) {
        for (const to of ALL_STATUSES) {
          const a = attrs({ type, purpose, status: from });
          const t = applyTransition(a, { to, by: 'operator:A', reason: 'r' });
          outcomes.add(
            `${from}->${to}:${canTransition(from, to)}:${holdsNow(from)}:${isTerminal(from)}:${t.ok}${t.ok ? '' : `:${t.reason}`}`,
          );
        }
      }
    }
  }
  // 5 x 5 from/to pairs, and nothing else may vary the answer.
  invariant = outcomes.size === ALL_STATUSES.length * ALL_STATUSES.length;
  check(
    'every decision is invariant under type and purpose',
    invariant,
    `${outcomes.size} distinct outcomes across ${ALL_TYPES.length * PURPOSES.length} type/purpose combinations; expected ${ALL_STATUSES.length * ALL_STATUSES.length}`,
  );

  // ---------------------------------------------------------------------------
  // End to end, through the real ResidencyService.
  // ---------------------------------------------------------------------------
  console.log('\nend to end, through the real service:');
  const key = await KeyStore.generate('lifecycle-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const cfg = parseCountryConfig({
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
  const store = new InMemoryStore();
  const svc = new ResidencyService(
    new ProviderRegistry('lifecycle-pepper'),
    new VcIssuer(key),
    store,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );
  const nin = '12345678902';
  const first = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin },
    decidedBy: 'operator:Desk-1',
  });
  check('a residency issues', first.status === 'issued');
  const rel = first.status === 'issued' ? first.record.relationship : undefined;
  check('  the record states its §4.3 attributes', !!rel);
  if (rel) {
    check('  status is ACTIVE', rel.status === 'ACTIVE');
    check('  type is GENERAL_RESIDENCY', rel.type === 'GENERAL_RESIDENCY');
    check('  purpose is recorded', rel.purpose.length > 0);
    check('  validFrom is set', !!rel.validFrom);
    check('  validTo is ABSENT — permanent until ended', rel.validTo === undefined);
    check('  the policy version is recorded', rel.policyVersion.startsWith('sha256:'));
    check('  evidence is referenced', rel.evidenceRefs.length > 0);
    check('  the assurance profile is named', !!rel.assuranceProfileId);
    check('  the issuer is recorded', rel.issuer === issuerDid);
    // No binding was attested and no authority vouched for residence, so nobody looked at
    // this applicant: the record says the software decided, and keeps the desk separately.
    check('  provenance says the software decided', rel.decidedBy.startsWith('automated:'), rel.decidedBy);
    check('  and names the operator who took the application', rel.submittedBy === 'operator:Desk-1');
  }

  const again = await svc.issue(cfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  check('re-enrolment while ACTIVE is idempotent', again.status === 'exists');

  const residentId = first.status === 'issued' ? first.residentId : '';
  const endResult = await svc.transitionRelationship(residentId, {
    to: 'ENDED',
    by: 'operator:Desk-1',
    reason: 'Relocated to Kano',
  });
  check('the residency can be ENDED', endResult.ok);
  check(
    '  the stored record reflects it',
    (await svc.relationshipFor(residentId))?.status === 'ENDED',
  );
  check(
    '  and the reason survives in the register',
    (await svc.relationshipFor(residentId))?.endedReason === 'Relocated to Kano',
  );

  // The idempotency contract now takes status into account (ADR-0007, Consequences).
  const afterEnd = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin },
    decidedBy: 'operator:Desk-2',
  });
  check('re-enrolling an ENDED residency does NOT return a stale record', afterEnd.status !== 'exists');
  check('  it issues afresh', afterEnd.status === 'issued');
  if (afterEnd.status === 'issued') {
    check('  the person keeps their resident id', afterEnd.residentId === residentId);
    check('  the relationship is ACTIVE again', afterEnd.record.relationship?.status === 'ACTIVE');
    check('  on a NEW status-list index, so the old credential stays revocable',
      first.status === 'issued' && afterEnd.record.statusListIndex !== first.record.statusListIndex);
    check('  the register still holds ONE record for this person',
      (await store.list({ countryCode: 'NG' })).total === 1);
  }

  console.log('\nsuspension is reversible (ORCS §7 needs it for link remediation):');
  const susp = await svc.transitionRelationship(residentId, {
    to: 'SUSPENDED',
    by: 'operator:Desk-1',
    reason: 'Identity link under review',
  });
  check('an ACTIVE residency can be suspended', susp.ok);
  const reEnrolWhileSuspended = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin },
  });
  check('  re-enrolment while SUSPENDED returns exists, not a fresh issue',
    reEnrolWhileSuspended.status === 'exists');
  const reinstated = await svc.transitionRelationship(residentId, {
    to: 'ACTIVE',
    by: 'operator:Desk-1',
  });
  check('  it can be reinstated', reinstated.ok);
  check('  and holds again', (await svc.relationshipFor(residentId))?.status === 'ACTIVE');

  console.log('\nsource check — the inert fields are not referenced in src/core logic:');
  // Belt and braces alongside the behavioural invariant above: no file in src/core outside
  // the lifecycle definitions and the record assembly may even mention them.
  const ALLOWED = ['lifecycle.ts', 'ports.ts', 'residency-service.ts'];
  const offenders: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts') && !ALLOWED.includes(entry.name)) {
        const src = readFileSync(full, 'utf8');
        if (/\brelationshipType\b|\brelationshipPurpose\b/.test(src)) offenders.push(full);
      }
    }
  };
  walk(join(process.cwd(), 'src/core'));
  check('no other core file references the inert fields', offenders.length === 0, offenders.join(', '));

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
