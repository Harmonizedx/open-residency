/* eslint-disable no-console */
/**
 * Residency policy engine — Phase 1 conformance.
 *
 * Proves the rights-preserving core of the policy engine: a deterministic, explainable
 * evaluator, and a sealed human-rights floor the merge resolver ENFORCES. The two
 * load-bearing checks are the ones the design calls the crux:
 *
 *   1. A pack that overrides a sealed field is REJECTED at merge (not silently dropped).
 *   2. A pack whose ordinary-residency rule references an origin/ancestry fact is REJECTED
 *      -- the indigene/settler discrimination cannot even be expressed. This is the
 *      mandatory anti-discrimination conformance case every pack must pass.
 *
 * Plus: the evaluator emits satisfiedRules/failedRules, and today's `ASSURANCE_RANK`
 * issuance gate is reproducible as a pack with no overrides (backward-compat).
 */
import { join } from 'node:path';
import { loadPack, parsePack } from '../src/core/policy-engine/pack-loader';
import { mergePacks, FloorViolationError } from '../src/core/policy-engine/floor';
import { evaluate } from '../src/core/policy-engine/evaluator';
import { PolicyPack, Facts } from '../src/core/policy-engine/types';

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

async function main() {
  console.log('\n== Residency policy engine — Phase 1 (evaluator + sealed rights floor) ==\n');

  // The real shipped floor pack.
  const floor = loadPack(join(process.cwd(), 'config/packs/global/residency-core.yaml'));
  check('the global floor pack loads and validates', floor.metadata.name === 'global/residency-core');
  check('the floor seals the national-identifier, inclusion, and origin fields', (floor.floor?.sealedFields ?? []).length === 3);
  check('the floor forbids origin/ancestry facts in ordinary_resident rules', (floor.floor?.forbiddenFactPaths?.ordinary_resident ?? []).includes('applicant.indigene'));

  // --- The evaluator is deterministic and explainable -----------------------
  console.log('\n-- evaluator --');
  const facts: Facts = {
    identity: { assuranceRank: 2, status: 'alive' },
    evidence: { authoritative: { count: 1 }, corroborative: { count: 0 } },
  };
  const ok = evaluate(floor, facts, 'ordinary_resident');
  check('an applicant with an authoritative record is approved', ok.decision === 'approved' && ok.residencyClass === 'ordinary_resident');
  check('the decision names the satisfied rule (explainable)', ok.satisfiedRules.includes('FLOOR-ORD-01'));
  check('the decision pins the policy version (reproducible)', ok.policyVersion === '2.0.0');

  // Inclusion: NO single document is mandatory -- attestation + verification also qualifies.
  const byAttestation = evaluate(floor, {
    identity: { assuranceRank: 1, status: 'alive' },
    evidence: { authoritative: { count: 0 }, corroborative: { count: 0 }, attestationWithVerification: true },
  }, 'ordinary_resident');
  check('an applicant with NO address document qualifies via attestation (inclusion)', byAttestation.decision === 'approved');

  // A rejection explains which conditions failed.
  const rejected = evaluate(floor, { identity: { assuranceRank: 0, status: 'alive' }, evidence: {} }, 'ordinary_resident');
  check('a failing applicant is rejected with the failed conditions listed', rejected.decision === 'rejected' && rejected.failedRules.length > 0);
  check('a deceased applicant is excluded even with good evidence', evaluate(floor, {
    identity: { assuranceRank: 3, status: 'deceased' }, evidence: { authoritative: { count: 5 } },
  }, 'ordinary_resident').decision === 'rejected');

  // Determinism: same inputs, same decision.
  check('the evaluator is deterministic (same facts -> same decision)', JSON.stringify(evaluate(floor, facts, 'ordinary_resident')) === JSON.stringify(evaluate(floor, facts, 'ordinary_resident')));

  // --- A clean jurisdiction pack merges and tightens the bar ----------------
  console.log('\n-- layered packs + sealed floor --');
  const cleanCountry: PolicyPack = parsePack({
    metadata: { name: 'jurisdictions/xx-region/residency', version: '2.1.0' },
    rules: {
      ordinary_resident: {
        id: 'XX-ORD-02',
        all: [
          { path: 'identity.assuranceRank', op: 'gte', value: 2 },
          { path: 'applicant.age', op: 'gte', value: 18 },
        ],
        any: [
          { path: 'evidence.authoritative.count', op: 'gte', value: 1 },
          { path: 'evidence.attestationWithVerification', op: 'eq', value: true },
        ],
      },
    },
    overrides: { 'credential.validity_days': 730 },
  });
  const merged = mergePacks(floor, cleanCountry);
  check('a clean jurisdiction pack merges onto the floor', merged.rules.ordinary_resident.id === 'XX-ORD-02');
  check('the jurisdiction may override a NON-sealed field (validity days)', merged.config?.['credential.validity_days'] === 730);
  check('the merged decision pins the jurisdiction policy version', evaluate(merged, { identity: { assuranceRank: 2 }, applicant: { age: 30 }, evidence: { authoritative: { count: 1 } } }, 'ordinary_resident').policyVersion === '2.1.0');

  // --- THE CRUX 1: a sealed-field override is REJECTED ----------------------
  let sealedRejected = false;
  let sealedErr: FloorViolationError | undefined;
  try {
    mergePacks(floor, parsePack({
      metadata: { name: 'bad/expose-nin', version: '1.0.0' },
      rules: {},
      overrides: { 'privacy.national_identifier.expose_in_credential': true }, // try to expose the NIN
    }));
  } catch (e) {
    sealedRejected = true;
    sealedErr = e as FloorViolationError;
  }
  check('a pack overriding a SEALED field is REJECTED at merge (not dropped)', sealedRejected && sealedErr?.kind === 'SEALED_FIELD');
  check('...and the rejection names the sealed field', sealedErr?.detail === 'privacy.national_identifier.expose_in_credential');

  // --- THE CRUX 2: the mandatory anti-discrimination case -------------------
  // A pack that tries to make ordinary residency depend on indigene/origin status.
  let originRejected = false;
  let originErr: FloorViolationError | undefined;
  try {
    mergePacks(floor, parsePack({
      metadata: { name: 'bad/indigene-only', version: '1.0.0' },
      rules: {
        ordinary_resident: {
          id: 'BAD-ORD',
          all: [{ path: 'identity.assuranceRank', op: 'gte', value: 1 }],
          exclusions: [{ path: 'applicant.indigene', op: 'eq', value: false }], // reject non-indigenes
        },
      },
    }));
  } catch (e) {
    originRejected = true;
    originErr = e as FloorViolationError;
  }
  check('MANDATORY: a pack gating ordinary residency on origin/indigene status is REJECTED', originRejected && originErr?.kind === 'FORBIDDEN_FACT_PATH');
  check('...and the rejection names the forbidden origin fact', (originErr?.detail ?? '').includes('applicant.indigene'));

  // The same forbidden fact is FINE in a different class (e.g. an explicit origin credential),
  // proving the guard is scoped to ordinary residency, not a blanket ban on the concept.
  let originCredentialOk = true;
  try {
    mergePacks(floor, parsePack({
      metadata: { name: 'jurisdictions/xx/origin', version: '1.0.0' },
      rules: {
        indigene_status: {
          id: 'XX-ORIGIN-01',
          all: [{ path: 'applicant.indigene', op: 'eq', value: true }], // legitimate: an ORIGIN credential
        },
      },
    }));
  } catch {
    originCredentialOk = false;
  }
  check('origin facts ARE allowed in a separate origin-credential class (scoped guard)', originCredentialOk);

  // --- Backward-compat: today's ASSURANCE_RANK gate as a pack ---------------
  console.log('\n-- backward compatibility --');
  // Today: issue iff achieved assurance rank >= required. Reproduce as a pack with one rule.
  const legacyPack: PolicyPack = parsePack({
    metadata: { name: 'legacy/assurance-gate', version: '0.0.0' },
    rules: { ordinary_resident: { id: 'LEGACY', all: [{ path: 'identity.assuranceRank', op: 'gte', value: 2 }] } },
  });
  // 'verified' == rank 2 in the current ASSURANCE_RANK; a 'verified' applicant passes, 'basic' (1) fails.
  check('legacy gate: a `verified` (rank 2) applicant is approved', evaluate(legacyPack, { identity: { assuranceRank: 2 } }, 'ordinary_resident').decision === 'approved');
  check('legacy gate: a `basic` (rank 1) applicant is rejected -- identical to today', evaluate(legacyPack, { identity: { assuranceRank: 1 } }, 'ordinary_resident').decision === 'rejected');

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
