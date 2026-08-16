// SPDX-License-Identifier: Apache-2.0

/**
 * The residency relationship's lifecycle: ORCS §6.2 status, §6.1 type, and the §4.3
 * attributes a relationship must state about itself.
 *
 * Implements [ADR-0007](../../../docs/adr/0007-residency-status-is-lifecycle.md). Before this,
 * a record could be created and erased but never *ended*: revoking the credential was the only
 * action available when someone left, so one lever carried two meanings -- "this credential is
 * dead" and "this person no longer resides here" -- and `revoke()` preserves no reason, so the
 * audit trail could not separate them afterwards.
 *
 * Two rules from that record govern this file.
 *
 * **Type and purpose are recorded and never read.** ORCS §4.3 lists both among the ten
 * attributes every relationship MUST specify, so they are stored. But the reason a person
 * resides somewhere must not determine what they can reach: residency here is foundational
 * trust, and gating on purpose would convert it into purpose-scoped permission. No function in
 * this file takes either as an argument, and `smoke:lifecycle` asserts that every decision is
 * invariant under both.
 *
 * **Nothing lapses on its own.** Validity is recorded because §4.3 requires it, but a record
 * whose `validTo` has passed is still ACTIVE until somebody ends it. Auto-expiry would withdraw
 * foundational trust from people who never stopped being resident -- silently, and hardest on
 * those least able to re-prove residence on a schedule.
 */

/**
 * ORCS §6.2 defines ten states. A single-jurisdiction deployment issues synchronously at an
 * enrolment desk -- there is no submission queue and no review board -- so DRAFT, SUBMITTED,
 * EVIDENCE_PENDING, UNDER_REVIEW and REJECTED describe a workflow this deployment does not
 * have. They are deliberately absent rather than present and unreachable: a state nothing can
 * enter is a claim the system cannot honour.
 *
 * EXPIRED is defined here but never entered by this implementation. It exists for a
 * jurisdiction that legislates fixed-term residency, and `endRelationship` will accept it as a
 * terminal state so such a deployment does not have to fork the vocabulary.
 */
export type RelationshipStatus = 'ACTIVE' | 'SUSPENDED' | 'ENDED' | 'REVOKED' | 'EXPIRED';

/**
 * ORCS §6.1 relationship types. A deployment holds one kind of relationship, so it records
 * GENERAL_RESIDENCY while the relationship holds and FORMER_RESIDENCY once it has ended.
 *
 * Recorded, never read. See the file header.
 */
export type RelationshipType = 'GENERAL_RESIDENCY' | 'FORMER_RESIDENCY';

/** Terminal states. Nothing transitions out of these. */
const TERMINAL: RelationshipStatus[] = ['ENDED', 'REVOKED', 'EXPIRED'];

/**
 * Permitted transitions, following ORCS §6.2:
 *
 *   ACTIVE -> SUSPENDED -> ACTIVE
 *          -> EXPIRED | ENDED | REVOKED
 *
 * SUSPENDED is reachable and reversible because ORCS §7 remediates a duplicate caused by an
 * identity-link error with "suspend affected relationship, unlink and re-evaluate" -- without
 * it, that remediation has no state to move through.
 */
const TRANSITIONS: Record<RelationshipStatus, RelationshipStatus[]> = {
  ACTIVE: ['SUSPENDED', 'ENDED', 'REVOKED', 'EXPIRED'],
  SUSPENDED: ['ACTIVE', 'ENDED', 'REVOKED', 'EXPIRED'],
  ENDED: [],
  REVOKED: [],
  EXPIRED: [],
};

export function isTerminal(status: RelationshipStatus): boolean {
  return TERMINAL.includes(status);
}

/**
 * Is this transition permitted?
 *
 * Takes only the two states. It deliberately cannot see type or purpose, which is the
 * enforcement of the read prohibition rather than a comment asking for it.
 */
export function canTransition(from: RelationshipStatus, to: RelationshipStatus): boolean {
  return TRANSITIONS[from]?.includes(to) ?? false;
}

/**
 * Does this relationship currently hold?
 *
 * ACTIVE only. A SUSPENDED relationship exists but is not to be relied on -- ORCS §7 suspends
 * precisely to restrict high-risk use while an link error is adjudicated -- and the terminal
 * states do not hold at all.
 *
 * Note what this does NOT do: it does not compare `validTo` to the clock. A record past its
 * recorded validity is still ACTIVE until somebody ends it (ADR-0007, Amendment 2).
 */
export function holdsNow(status: RelationshipStatus): boolean {
  return status === 'ACTIVE';
}

/**
 * The ORCS §4.3 attributes a relationship states about itself.
 *
 * Jurisdiction is the tenth attribute and is not repeated here: it is already `countryCode`
 * and `subnationalUnit` on the record, and duplicating it would create two places to disagree.
 */
export interface RelationshipAttributes {
  /** §4.3 type. Recorded, never read. */
  type: RelationshipType;
  /** §4.3 purpose. Recorded, never read. Free text: this deployment does not interpret it. */
  purpose: string;
  /** §4.3 status. */
  status: RelationshipStatus;
  /** §4.3 validity — start. */
  validFrom: string;
  /** §4.3 validity — end. Absent means permanent until ended, which is the default. */
  validTo?: string;
  /** §4.3 policy version: the ruleset the issuing decision was taken under. */
  policyVersion: string;
  /** §4.3 evidence references: what the decision rested on, by reference rather than value. */
  evidenceRefs: string[];
  /** §4.3 assurance profile: the governed profile id the assurance value resolved to. */
  assuranceProfileId?: string;
  /** §4.3 issuer: the authority that decided, as a DID. */
  issuer: string;
  /** §4.3 decision provenance. */
  decidedBy: string;
  decidedAt: string;
  /** Set when the relationship reached a terminal state. */
  endedAt?: string;
  endedReason?: string;
  endedBy?: string;
}

export interface TransitionRequest {
  to: RelationshipStatus;
  /** Who decided. An operator id, never a bare "system". */
  by: string;
  /** Why. Required for a terminal transition; ORCS §10 asks the same of revocation. */
  reason?: string;
  at?: string;
}

export type TransitionOutcome =
  | { ok: true; attributes: RelationshipAttributes }
  | { ok: false; reason: string };

/**
 * Apply a transition, returning the new attributes or a refusal.
 *
 * A terminal transition MUST carry a reason. This is the whole point of separating ending a
 * residency from revoking a credential: `revoke()` preserves no reason (ORCS §10, finding
 * G-07), which is why a revoked credential today cannot be distinguished from a person who
 * moved away. Ending without a reason would rebuild that ambiguity in the new field.
 */
export function applyTransition(
  current: RelationshipAttributes,
  req: TransitionRequest,
): TransitionOutcome {
  if (!canTransition(current.status, req.to)) {
    return {
      ok: false,
      reason: isTerminal(current.status)
        ? `RELATIONSHIP_ALREADY_${current.status}`
        : `TRANSITION_NOT_PERMITTED_${current.status}_TO_${req.to}`,
    };
  }
  if (isTerminal(req.to) && !req.reason?.trim()) {
    return { ok: false, reason: `REASON_REQUIRED_FOR_${req.to}` };
  }
  if (!req.by?.trim()) {
    return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
  }

  const at = req.at ?? new Date().toISOString();
  const next: RelationshipAttributes = {
    ...current,
    status: req.to,
    decidedBy: req.by,
    decidedAt: at,
  };

  if (isTerminal(req.to)) {
    next.endedAt = at;
    next.endedReason = req.reason!.trim();
    next.endedBy = req.by;
    // §6.1 supplies the type for a relationship that no longer holds. Recorded, never read.
    next.type = 'FORMER_RESIDENCY';
    // Validity closes at the moment the relationship stopped holding, so the recorded period
    // matches what actually happened rather than staying open on a terminated record.
    next.validTo = at;
  }

  if (req.to === 'ACTIVE' && isTerminal(current.status)) {
    // Unreachable via canTransition; kept as a guard because a future edit to TRANSITIONS
    // that permitted it would otherwise silently resurrect a terminated relationship.
    return { ok: false, reason: 'CANNOT_REACTIVATE_TERMINAL_RELATIONSHIP' };
  }

  return { ok: true, attributes: next };
}

/** The attributes a newly issued relationship starts with. */
export function newRelationship(input: {
  purpose: string;
  policyVersion: string;
  evidenceRefs: string[];
  assuranceProfileId?: string;
  issuer: string;
  decidedBy: string;
  at: string;
}): RelationshipAttributes {
  const attrs: RelationshipAttributes = {
    type: 'GENERAL_RESIDENCY',
    purpose: input.purpose,
    status: 'ACTIVE',
    validFrom: input.at,
    // No validTo: permanent until ended (ADR-0007, Amendment 2).
    policyVersion: input.policyVersion,
    evidenceRefs: input.evidenceRefs,
    issuer: input.issuer,
    decidedBy: input.decidedBy,
    decidedAt: input.at,
  };
  if (input.assuranceProfileId) attrs.assuranceProfileId = input.assuranceProfileId;
  return attrs;
}

/**
 * The default every record predating this change is read as.
 *
 * ORRA §15 asks for additive migration, and [ADR-0006](../../../docs/adr/0006-additive-migration-resident-facade.md)
 * keeps `Resident` as the write-through facade. An existing row was issued and never ended, so
 * ACTIVE is the truthful reading; the provenance says plainly that it was backfilled rather
 * than decided, so nobody mistakes it for a recorded decision.
 */
export const BACKFILLED_PROVENANCE = 'migration:pre-lifecycle-record';

/**
 * Read a record's relationship attributes, supplying the backfill for rows written before
 * this existed.
 *
 * Every caller goes through here rather than touching `record.relationship` directly, so a
 * pre-lifecycle row can never be mistaken for one with no status at all -- which would read as
 * falsy and, in a boolean test, as "not active".
 */
export function relationshipOf(record: {
  relationship?: RelationshipAttributes;
  createdAt: string;
}): RelationshipAttributes {
  if (record.relationship) return record.relationship;
  return {
    type: 'GENERAL_RESIDENCY',
    purpose: '',
    status: 'ACTIVE',
    validFrom: record.createdAt,
    policyVersion: BACKFILLED_PROVENANCE,
    evidenceRefs: [],
    issuer: '',
    decidedBy: BACKFILLED_PROVENANCE,
    decidedAt: record.createdAt,
  };
}