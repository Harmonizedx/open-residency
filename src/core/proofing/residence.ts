/**
 * Proof of residence.
 *
 * Foundational verification answers "is this a genuine identity, and does the applicant
 * own it?". It does NOT answer "does this person actually live in the subnational unit
 * they are claiming residency in?" -- a separate, local, and legally-scoped question that
 * no national ID API settles on its own. This module models that question the same way
 * `binding.ts` models owner-proof: as evidence of a declared strength, evaluated against a
 * jurisdiction's policy, rather than a trusted string.
 *
 * Two hazards this design exists to prevent:
 *
 *  1. Treating a recorded label as proof. Previously `proofOfResidence` was written into
 *     the credential but never enforced. Here residence becomes a real accept/reject gate,
 *     parallel to applicant binding and foundational assurance.
 *
 *  2. Confusing RESIDENCE with ORIGIN. A national record (e.g. Nigeria's NIN) often returns
 *     both `state of residence` and `state of origin`. Origin is indigeneity/heritage -- it
 *     is static, tied to lineage, and using it as residence is both wrong and a
 *     discrimination vector (the indigene-vs-settler problem). Origin is never an accepted
 *     residence method; the foundational layer keeps the two fields separate and only the
 *     residence field is ever offered here as evidence.
 *
 * The interoperable currency is a Residence Assurance Level (RAL), mirroring the
 * foundational assurance ladder. A relying party reads the level; how a given jurisdiction
 * reaches it is configurable and locally governed.
 */

/** Residence Assurance Level. RAL0 self-declared .. RAL3 authoritative register of record. */
export type ResidenceAssuranceLevel = 'RAL0' | 'RAL1' | 'RAL2' | 'RAL3';

export const RESIDENCE_LEVEL_RANK: Record<ResidenceAssuranceLevel, number> = {
  RAL0: 0,
  RAL1: 1,
  RAL2: 2,
  RAL3: 3,
};

const LEVELS: ResidenceAssuranceLevel[] = ['RAL0', 'RAL1', 'RAL2', 'RAL3'];

/** The lower (weaker) of two levels. */
function minLevel(a: ResidenceAssuranceLevel, b: ResidenceAssuranceLevel): ResidenceAssuranceLevel {
  return RESIDENCE_LEVEL_RANK[a] <= RESIDENCE_LEVEL_RANK[b] ? a : b;
}

export type ResidenceEvidenceMethod =
  /** No residence evidence: the applicant merely stated where they live. Not proof. */
  | 'self_declared'
  /** A residence locality returned by the foundational provider's own record. Usually
   *  self-declared to that register and often stale, so it is capped low by default. */
  | 'register_declared_residence'
  /** A ward-level operator or an existing local register vouches that the person resides. */
  | 'authority_attestation'
  /** An uploaded documentary proof (utility record, tenancy, etc.). */
  | 'document'
  /** A captured location matched to the unit's boundary (open location code / polygon). */
  | 'geospatial_match';

export interface ResidenceEvidence {
  method: ResidenceEvidenceMethod;
  /** The subnational unit code this evidence points at, AFTER reconciliation to the
   *  deployment's unit taxonomy. Undefined if the reported locality could not be mapped. */
  adminUnit?: string;
  /** The raw locality string the provider/operator reported, kept for audit. */
  reportedUnit?: string;
  /** ISO date the evidence reflects (when residence was captured/attested). Missing => stale. */
  asOf?: string;
  /** Opaque reference: an attestation id, a document id, a register transaction. */
  ref?: string;
}

/** The maximum RAL each method can yield on its own, before recency/unit-match downgrades. */
export const DEFAULT_METHOD_CEILING: Record<ResidenceEvidenceMethod, ResidenceAssuranceLevel> = {
  self_declared: 'RAL0',
  register_declared_residence: 'RAL1',
  document: 'RAL2',
  authority_attestation: 'RAL2',
  geospatial_match: 'RAL2',
};

export interface ResidencePolicy {
  /** When true, issuance is refused unless `targetLevel` is reached for the claimed unit. */
  required: boolean;
  /** The RAL that must be achieved for issuance when `required`. */
  targetLevel: ResidenceAssuranceLevel;
  /** Which evidence methods this jurisdiction accepts. `self_declared` is always allowed
   *  as the RAL0 floor but never counts toward a required level above RAL0. */
  acceptedMethods: ResidenceEvidenceMethod[];
  /** Require the evidence's reconciled unit to equal the claimed unit. Recommended. */
  unitMatchRequired: boolean;
  /** Evidence older than this (or undated) is capped at RAL1 -- it cannot reach RAL2+. */
  recencyDays?: number;
  /** Per-method ceiling overrides, merged over DEFAULT_METHOD_CEILING. */
  methodCeiling?: Partial<Record<ResidenceEvidenceMethod, ResidenceAssuranceLevel>>;
  /** Auto-collect the residence locality returned by the foundational provider as
   *  `register_declared_residence` evidence. Off by default: a deployment opts in. */
  acceptFoundationalResidence: boolean;
}

/** A permissive default used when a config declares no residence policy: record, never gate. */
export const DEFAULT_RESIDENCE_POLICY: ResidencePolicy = {
  required: false,
  targetLevel: 'RAL1',
  acceptedMethods: [
    'register_declared_residence',
    'authority_attestation',
    'document',
    'geospatial_match',
  ],
  unitMatchRequired: true,
  acceptFoundationalResidence: false,
};

export interface ResidenceOutcome {
  level: ResidenceAssuranceLevel;
  /** Whether the achieved level meets the policy (always true when the policy is not required). */
  satisfied: boolean;
  /** The winning evidence method ('self_declared' when nothing else qualified). */
  method: ResidenceEvidenceMethod;
  /** The reconciled unit the achieved residence is anchored to, when known. */
  unit?: string;
  asOf?: string;
  /** Machine-readable reason when a required policy is not satisfied. */
  reason?: string;
}

/** Case-insensitive normalization for comparing unit codes/names. */
function norm(s: string): string {
  return s.trim().toUpperCase();
}

/**
 * Map a provider/operator-reported locality onto a deployment's subnational unit code.
 * Matches by unit code first, then by unit name. Returns undefined when nothing matches --
 * an unmapped locality must not silently pass a unit-match check.
 */
export function reconcileUnit(
  units: Array<{ code: string; name: string }>,
  reported?: string,
): string | undefined {
  if (!reported) return undefined;
  const r = norm(reported);
  const byCode = units.find((u) => norm(u.code) === r);
  if (byCode) return byCode.code;
  const byName = units.find((u) => norm(u.name) === r);
  return byName?.code;
}

/** Whole days between an ISO date and a reference instant; Infinity when undated/unparseable. */
function ageInDays(asOf: string | undefined, nowIso: string): number {
  if (!asOf) return Infinity;
  const then = Date.parse(asOf);
  const now = Date.parse(nowIso);
  if (Number.isNaN(then) || Number.isNaN(now)) return Infinity;
  return (now - then) / 86_400_000;
}

/**
 * Evaluate residence evidence against a policy for a specific claimed unit.
 *
 * The achieved level is the strongest any single accepted, unit-matched, sufficiently
 * recent evidence yields. `self_declared` establishes the RAL0 floor and never more.
 */
export function evaluateResidence(
  policy: ResidencePolicy,
  evidences: ResidenceEvidence[],
  claimedUnit: string,
  nowIso: string,
): ResidenceOutcome {
  const ceiling = { ...DEFAULT_METHOD_CEILING, ...(policy.methodCeiling ?? {}) };
  const claim = norm(claimedUnit);

  let best: ResidenceOutcome = { level: 'RAL0', satisfied: false, method: 'self_declared' };

  for (const ev of evidences) {
    // Origin and any non-accepted method contribute nothing. self_declared is only ever
    // the floor, so it is skipped here (best starts at RAL0/self_declared already).
    if (ev.method === 'self_declared' || !policy.acceptedMethods.includes(ev.method)) continue;

    // Unit match: evidence pointing at another unit (or nowhere) cannot prove residence here.
    const unitMatches = ev.adminUnit != null && norm(ev.adminUnit) === claim;
    if (policy.unitMatchRequired && !unitMatches) continue;

    let level = ceiling[ev.method];

    // Recency: undated or stale evidence cannot reach RAL2+.
    if (policy.recencyDays != null && ageInDays(ev.asOf, nowIso) > policy.recencyDays) {
      level = minLevel(level, 'RAL1');
    }

    if (RESIDENCE_LEVEL_RANK[level] > RESIDENCE_LEVEL_RANK[best.level]) {
      best = {
        level,
        satisfied: false,
        method: ev.method,
        unit: ev.adminUnit,
        asOf: ev.asOf,
      };
    }
  }

  const meetsTarget = RESIDENCE_LEVEL_RANK[best.level] >= RESIDENCE_LEVEL_RANK[policy.targetLevel];
  best.satisfied = !policy.required || meetsTarget;
  if (policy.required && !meetsTarget) {
    best.reason = `PROOF_OF_RESIDENCE_BELOW_${policy.targetLevel}_GOT_${best.level}`;
  }
  return best;
}

export { LEVELS as RESIDENCE_LEVELS };
