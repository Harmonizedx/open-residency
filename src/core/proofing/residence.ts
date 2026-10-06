// SPDX-License-Identifier: Apache-2.0
import { ResidenceAddress, ResidenceAnchor, addressesMatch } from './address';
import { canonicalUnitCode } from '../config/iso3166-2';
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

/**
 * Who vouched, when the method is `authority_attestation`.
 *
 * Every register that accepts community attestation names the kind of attester it accepts:
 * South Africa's ward councillor or traditional leader, Kenya's chief, India's gazetted
 * officer, a camp manager for people in displacement, a landlord or host for a lodger. A
 * jurisdiction lists the kinds it accepts; an attestation from an unlisted kind is real
 * information and no evidence. `other` is deliberately available so a register is not forced
 * to misfile an attester the vocabulary did not anticipate -- a policy that lists `other`
 * accepts that. This vocabulary is a project profile, not a standard.
 */
export type AttesterType =
  | 'ward_officer'
  | 'registrar'
  | 'traditional_ruler'
  | 'ward_councillor'
  | 'religious_leader'
  | 'camp_manager'
  | 'landlord_or_host'
  | 'employer'
  | 'institution'
  | 'other';

export const ATTESTER_TYPES: readonly AttesterType[] = [
  'ward_officer',
  'registrar',
  'traditional_ruler',
  'ward_councillor',
  'religious_leader',
  'camp_manager',
  'landlord_or_host',
  'employer',
  'institution',
  'other',
];

/**
 * How the applicant resides, as distinct from where.
 *
 * `dwelling` -- the ordinary case: the person lives at a dwelling in the unit (and, under
 * address anchoring, at the address claimed).
 *
 * `reference_address` -- the person has no dwelling of their own and uses an address for
 * contact and registration: a shelter, a relative, an institution. Belgium's referentieadres
 * and the Netherlands' briefadres are the statutory forms. Residence in the UNIT is still what
 * is being established; the address is not where they sleep, so it is not matched as one.
 *
 * `no_fixed_abode` -- the person resides in the unit and has no address at all: street
 * homelessness, a displacement camp, a host community. Every mature register has this escape
 * hatch, because a register that cannot hold these people excludes exactly those who most
 * need to be counted. Only an attestation by an accepted attester can establish it.
 *
 * A mode is recorded with the residence and never carried into the credential: whether a
 * holder has a fixed address is nobody's business at a service counter.
 */
export type ResidenceMode = 'dwelling' | 'reference_address' | 'no_fixed_abode';

export const RESIDENCE_MODES: readonly ResidenceMode[] = ['dwelling', 'reference_address', 'no_fixed_abode'];

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
  /**
   * The address this evidence attests to, where the jurisdiction anchors on addresses.
   * Ignored entirely under `anchor: 'unit'`, which is the default.
   */
  address?: ResidenceAddress;
  /**
   * ISO date this evidence says residence BEGAN, where it says so: a tenancy's start date, the
   * date a ward register first recorded the person, the move-in date on an attestation.
   * Distinct from `asOf` (when the evidence was captured). This is what a minimum-duration rule
   * is measured from; absent, the rule falls back to what the applicant declared.
   */
  since?: string;
  /** Who vouched, for `authority_attestation`. Required when the policy lists accepted kinds. */
  attesterType?: AttesterType;
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
  /**
   * What residence is anchored to. `unit` (the default) keeps the administrative-unit model;
   * `address` additionally requires the evidence to name the same address the applicant
   * claims. See `core/proofing/address.ts` for why this is a jurisdiction's choice.
   */
  anchor?: ResidenceAnchor;
  /** Evidence older than this (or undated) is capped at RAL1 -- it cannot reach RAL2+. */
  recencyDays?: number;
  /** Per-method ceiling overrides, merged over DEFAULT_METHOD_CEILING. */
  methodCeiling?: Partial<Record<ResidenceEvidenceMethod, ResidenceAssuranceLevel>>;
  /** Auto-collect the residence locality returned by the foundational provider as
   *  `register_declared_residence` evidence. Off by default: a deployment opts in. */
  acceptFoundationalResidence: boolean;
  /**
   * The residence rule, where the jurisdiction's law has one: how long a person must have
   * resided before the register may hold them (Kaduna: six months; Lagos: three; Korea: thirty
   * days). Measured from the strongest evidence's `since`, else the applicant's declaration.
   * Absent means no duration test, which is most of the world. Only enforced when `required`.
   */
  minimumDurationDays?: number;
  /**
   * Whether a declared intention to reside satisfies the duration rule on its own, as it does
   * under the Kaduna law ("resident for six months OR intending to reside") and Korea's.
   * Off by default: intent is a statement, and a jurisdiction opts in to counting it.
   */
  intentToResideSuffices?: boolean;
  /** Which kinds of attester an `authority_attestation` is accepted from. Absent: any. */
  attestation?: { acceptedAttesterTypes?: AttesterType[] };
  /**
   * The residence modes this jurisdiction admits beyond an ordinary dwelling. Each is off
   * unless allowed, and each may narrow the attesters it accepts; `no_fixed_abode` may also
   * cap the level it can reach, since there is less to corroborate.
   */
  modes?: {
    referenceAddress?: { allowed: boolean; acceptedAttesterTypes?: AttesterType[] };
    noFixedAbode?: {
      allowed: boolean;
      acceptedAttesterTypes?: AttesterType[];
      ceiling?: ResidenceAssuranceLevel;
    };
  };
}

/** What the applicant declared about their residence, as distinct from what evidence says. */
export interface DeclaredResidence {
  /** ISO date residence began, by the applicant's own account. Used only when no evidence states one. */
  since?: string;
  /** The applicant intends to reside here. Counts only where the policy says it does. */
  intentToReside?: boolean;
  /** How the applicant resides. Defaults to `dwelling`. */
  mode?: ResidenceMode;
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
  /** The address the achieved residence is anchored to, under address anchoring. */
  address?: ResidenceAddress;
  /** The reconciled unit the achieved residence is anchored to, when known. */
  unit?: string;
  asOf?: string;
  /** When residence began, from the winning evidence or else the declaration. */
  since?: string;
  /** How the applicant resides. Recorded, never carried into the credential. */
  mode?: ResidenceMode;
  /** Who vouched, when the winning evidence was an attestation. */
  attesterType?: AttesterType;
  /** Whether the applicant declared an intention to reside. */
  intentDeclared?: boolean;
  /** Machine-readable reason when a required policy is not satisfied. */
  reason?: string;
}

/** Case-insensitive normalization for comparing unit codes/names. */
function norm(s: string): string {
  return s.trim().toUpperCase();
}

/**
 * Map a provider/operator-reported locality onto a deployment's subnational unit code.
 *
 * Matches by unit code first, then by the unit's declared ISO 3166-2 code, then by unit name,
 * and always returns the unit's own `code` -- the form records carry -- never the form that
 * was reported. Code comparison is tolerant of the ISO country prefix: a register that says
 * `NI` and a config that says `NG-NI` (or the reverse) agree, because they name the same unit
 * and the difference is notation, not fact. Nothing else is normalised: `Niger` and `Niger
 * State` are different strings to this function, by design (see `address.ts` for why the core
 * does not guess at one country's abbreviations).
 *
 * Returns undefined when nothing matches -- an unmapped locality must not silently pass a
 * unit-match check.
 */
export function reconcileUnit(
  units: Array<{ code: string; name: string; iso3166_2?: string }>,
  reported?: string,
  /**
   * The deployment's country, so that only ITS prefix is treated as notation. Without it a
   * full ISO code keeps its prefix and matches only another full code: `GH-NI` never becomes
   * Niger. Callers inside a deployment should always pass `cfg.countryCode`.
   */
  countryCode?: string,
): string | undefined {
  if (!reported) return undefined;
  const r = canonicalUnitCode(reported, countryCode);
  const byCode = units.find((u) => canonicalUnitCode(u.code, countryCode) === r);
  if (byCode) return byCode.code;
  const byIso = units.find(
    (u) => u.iso3166_2 != null && canonicalUnitCode(u.iso3166_2, countryCode) === r,
  );
  if (byIso) return byIso.code;
  const rn = norm(reported);
  const byName = units.find((u) => norm(u.name) === rn);
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
  /**
   * The address the applicant claims to reside at. Required under `anchor: 'address'` and
   * ignored otherwise, so a unit-anchored jurisdiction is entirely unaffected by this
   * parameter existing.
   */
  claimedAddress?: ResidenceAddress,
  /** What the applicant declared: when residence began, intent, and how they reside. */
  declared?: DeclaredResidence,
): ResidenceOutcome {
  const ceiling = { ...DEFAULT_METHOD_CEILING, ...(policy.methodCeiling ?? {}) };
  const claim = norm(claimedUnit);
  const mode: ResidenceMode = declared?.mode ?? 'dwelling';

  let best: ResidenceOutcome = { level: 'RAL0', satisfied: false, method: 'self_declared' };

  // A mode the jurisdiction has not admitted contributes nothing, whatever the evidence: the
  // refusal names the mode so the applicant is told what was not accepted, rather than being
  // told their proof was weak when it was their situation that was not provided for.
  const modeRule =
    mode === 'reference_address'
      ? policy.modes?.referenceAddress
      : mode === 'no_fixed_abode'
        ? policy.modes?.noFixedAbode
        : undefined;
  const modeAdmitted = mode === 'dwelling' || modeRule?.allowed === true;

  for (const ev of modeAdmitted ? evidences : []) {
    // Origin and any non-accepted method contribute nothing. self_declared is only ever
    // the floor, so it is skipped here (best starts at RAL0/self_declared already).
    if (ev.method === 'self_declared' || !policy.acceptedMethods.includes(ev.method)) continue;

    // Unit match: evidence pointing at another unit (or nowhere) cannot prove residence here.
    const unitMatches = ev.adminUnit != null && norm(ev.adminUnit) === claim;
    if (policy.unitMatchRequired && !unitMatches) continue;

    // Address match, where the jurisdiction anchors on addresses. Strictly ADDITIONAL to the
    // unit check, never instead of it: a German municipality still has to establish the
    // address is in its own municipality, and an address alone does not say that.
    //
    // Evidence carrying no address cannot prove residence at an address, however strong the
    // method. A ward officer's attestation that somebody "lives in Rigasa" is real evidence
    // about a unit and says nothing about which door -- treating it as address proof would
    // silently downgrade what address anchoring means.
    if (mode === 'dwelling' && policy.anchor === 'address' && !addressesMatch(ev.address, claimedAddress)) {
      continue;
    }

    // Outside an ordinary dwelling, only somebody vouching can establish residence: there is
    // no tenancy to produce and no address to match, and a register field or a geospatial fix
    // says where a person was, not that they live here. So in those modes an attestation is
    // the only admissible method, and the mode may narrow which attesters it accepts.
    if (mode !== 'dwelling' && ev.method !== 'authority_attestation') continue;

    // Attester gate: an attestation from a kind of attester the jurisdiction (or this mode)
    // does not accept is information, not evidence. A listed policy with no attesterType on
    // the evidence fails the gate: the kind must be stated, not assumed.
    if (ev.method === 'authority_attestation') {
      const accepted = modeRule?.acceptedAttesterTypes ?? policy.attestation?.acceptedAttesterTypes;
      if (accepted && (ev.attesterType == null || !accepted.includes(ev.attesterType))) continue;
    }

    let level = ceiling[ev.method];

    // No fixed abode: less to corroborate, so the jurisdiction may cap what it can reach.
    if (mode === 'no_fixed_abode' && policy.modes?.noFixedAbode?.ceiling) {
      level = minLevel(level, policy.modes.noFixedAbode.ceiling);
    }

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
        address: ev.address,
        asOf: ev.asOf,
        since: ev.since,
        attesterType: ev.attesterType,
      };
    }
  }

  // The duration rule. Evidence that states when residence began outranks the applicant's
  // account; the applicant's account is used only when no evidence speaks to it. An intention
  // to reside satisfies the rule only where the jurisdiction has said so. A missing date under
  // a duration rule is its own reason -- "we could not tell how long" is a different thing to
  // tell an applicant than "not long enough", and a different thing for them to fix.
  const since = best.since ?? declared?.since;
  let durationReason: string | undefined;
  if (policy.minimumDurationDays != null) {
    const intentSuffices = declared?.intentToReside === true && policy.intentToResideSuffices === true;
    if (!intentSuffices) {
      if (!since) durationReason = 'RESIDENCE_DURATION_UNKNOWN';
      else if (ageInDays(since, nowIso) < policy.minimumDurationDays) {
        durationReason = `RESIDENCE_DURATION_BELOW_MINIMUM_${policy.minimumDurationDays}D`;
      }
    }
  }

  best.since = since;
  best.mode = mode;
  if (declared?.intentToReside != null) best.intentDeclared = declared.intentToReside;

  const meetsTarget = RESIDENCE_LEVEL_RANK[best.level] >= RESIDENCE_LEVEL_RANK[policy.targetLevel];
  best.satisfied = !policy.required || (modeAdmitted && meetsTarget && durationReason == null);
  if (policy.required && !best.satisfied) {
    best.reason = !modeAdmitted
      ? `RESIDENCE_MODE_NOT_ACCEPTED_${mode}`
      : !meetsTarget
        ? `PROOF_OF_RESIDENCE_BELOW_${policy.targetLevel}_GOT_${best.level}`
        : durationReason;
  }
  return best;
}

export { LEVELS as RESIDENCE_LEVELS };
