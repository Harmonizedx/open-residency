/**
 * Jurisdictional relationships — ORCS §6.
 *
 * The specification's central move is that residency is *not* a boolean attribute of a
 * person, and not an exclusive claim by one government. It is a purpose-bound relationship
 * between a person and a jurisdiction, and a person may hold several at once:
 *
 *   family home in Katsina · employment in Kano · study in Lagos
 *
 * all three ACTIVE, all three legitimate, none of them in conflict. Modelling residency as
 * one row per person makes that unrepresentable, and — worse — makes the second relationship
 * look like a duplicate to be reconciled away.
 *
 * This module supplies the two vocabularies that turn a residency row into a relationship:
 * what the relationship is *for* (§6.1) and where it is in its life (§6.2). Both are closed
 * sets on purpose. A free-text purpose cannot be reasoned about by a conflict rule, and a
 * free-text status cannot be guarded.
 */

/**
 * ORCS §6.1. The eleven relationship types, verbatim and closed.
 *
 * A jurisdiction that needs a distinction these do not carry adds it as a *purpose* within a
 * type, never as a twelfth type — the set is what lets a conflict rule written in one
 * deployment mean the same thing in another.
 */
export const RELATIONSHIP_TYPES = [
  'GENERAL_RESIDENCY',
  'ORDINARY_RESIDENCY',
  'TEMPORARY_RESIDENCY',
  'EMPLOYMENT_CONNECTION',
  'EDUCATION_CONNECTION',
  'TAX_CONNECTION',
  'HEALTH_SERVICE_CONNECTION',
  'BUSINESS_CONNECTION',
  'AGRICULTURAL_CONNECTION',
  'DISPLACEMENT_CONNECTION',
  'FORMER_RESIDENCY',
] as const;

export type RelationshipType = (typeof RELATIONSHIP_TYPES)[number];

export function isRelationshipType(v: string): v is RelationshipType {
  return (RELATIONSHIP_TYPES as readonly string[]).includes(v);
}

/**
 * ORCS §6.2 relationship lifecycle:
 *
 *   DRAFT -> SUBMITTED -> EVIDENCE_PENDING -> UNDER_REVIEW
 *         -> ACTIVE -> SUSPENDED -> ACTIVE
 *         -> EXPIRED | ENDED | REVOKED | REJECTED
 *
 * `provisional: boolean` covered two of these nine. The missing states are the ones that
 * carry process: an application waiting on a document sits in EVIDENCE_PENDING, a contested
 * relationship sits in SUSPENDED rather than being revoked, and ORCS §7's remedy for a
 * data-quality conflict ("suspend, unlink, re-evaluate") needs SUSPENDED to exist at all.
 */
export const RELATIONSHIP_STATUSES = [
  'DRAFT',
  'SUBMITTED',
  'EVIDENCE_PENDING',
  'UNDER_REVIEW',
  'ACTIVE',
  'SUSPENDED',
  'EXPIRED',
  'ENDED',
  'REVOKED',
  'REJECTED',
] as const;

export type RelationshipStatus = (typeof RELATIONSHIP_STATUSES)[number];

/** States from which no transition is permitted. ENDED and EXPIRED are terminal for this
 *  relationship; a person who returns gets a new relationship, preserving the old one. */
export const TERMINAL_STATUSES: readonly RelationshipStatus[] = [
  'EXPIRED',
  'ENDED',
  'REVOKED',
  'REJECTED',
];

/**
 * Permitted transitions. Anything absent is refused — the point of a guarded machine is that
 * an unlisted move is a bug, not an undocumented feature.
 *
 * Note SUSPENDED -> ACTIVE: suspension is explicitly reversible in §6.2, which is what
 * separates it from revocation. Note also that every non-terminal state may reach REVOKED:
 * an authority that discovers fraud does not have to walk the record forward first.
 */
const TRANSITIONS: Record<RelationshipStatus, readonly RelationshipStatus[]> = {
  DRAFT: ['SUBMITTED', 'REJECTED'],
  SUBMITTED: ['EVIDENCE_PENDING', 'UNDER_REVIEW', 'ACTIVE', 'REJECTED', 'REVOKED'],
  EVIDENCE_PENDING: ['UNDER_REVIEW', 'ACTIVE', 'REJECTED', 'REVOKED'],
  UNDER_REVIEW: ['ACTIVE', 'REJECTED', 'REVOKED'],
  ACTIVE: ['SUSPENDED', 'EXPIRED', 'ENDED', 'REVOKED'],
  SUSPENDED: ['ACTIVE', 'ENDED', 'REVOKED', 'EXPIRED'],
  EXPIRED: [],
  ENDED: [],
  REVOKED: [],
  REJECTED: [],
};

export function canTransition(from: RelationshipStatus, to: RelationshipStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

/** Every status reachable from `from` in one step. Empty for terminal states. */
export function allowedTransitions(from: RelationshipStatus): readonly RelationshipStatus[] {
  return TRANSITIONS[from];
}

export function isTerminal(status: RelationshipStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

/**
 * A relationship counts as live — for claim release, credential issuance and conflict
 * evaluation — only when ACTIVE. SUSPENDED deliberately does not qualify: the whole reason
 * to suspend rather than revoke is to stop claim release while preserving the record and
 * the appeal path.
 */
export function isLive(status: RelationshipStatus): boolean {
  return status === 'ACTIVE';
}

export class RelationshipTransitionError extends Error {
  constructor(
    readonly from: RelationshipStatus,
    readonly to: RelationshipStatus,
  ) {
    super(
      `Illegal relationship transition ${from} -> ${to}. ` +
        `Permitted from ${from}: ${allowedTransitions(from).join(', ') || '(terminal)'}`,
    );
    this.name = 'RelationshipTransitionError';
  }
}

/**
 * Apply a transition, or refuse it.
 *
 * ORCS §4.3 requires decision provenance on every relationship, so a transition carries who
 * moved it and why rather than only what it became. A status change with no attributable
 * actor is exactly what makes an audit trail undefendable later.
 */
export interface TransitionInput {
  from: RelationshipStatus;
  to: RelationshipStatus;
  actor: string;
  reason?: string;
  at?: string;
}

export interface TransitionResult {
  status: RelationshipStatus;
  actor: string;
  reason?: string;
  at: string;
}

export function transition(input: TransitionInput): TransitionResult {
  if (!canTransition(input.from, input.to)) {
    throw new RelationshipTransitionError(input.from, input.to);
  }
  return {
    status: input.to,
    actor: input.actor,
    reason: input.reason,
    at: input.at ?? new Date().toISOString(),
  };
}

/**
 * The default purpose for a relationship type, used when a caller states a type but no
 * purpose. Purposes are free-form per jurisdiction (ORCS §4.3 requires only that one is
 * recorded), so this is a starting vocabulary, not a closed set.
 */
export const DEFAULT_PURPOSE: Record<RelationshipType, string> = {
  GENERAL_RESIDENCY: 'general_administrative_residence',
  ORDINARY_RESIDENCY: 'ordinary_residence',
  TEMPORARY_RESIDENCY: 'temporary_residence',
  EMPLOYMENT_CONNECTION: 'employment',
  EDUCATION_CONNECTION: 'education',
  TAX_CONNECTION: 'taxation',
  HEALTH_SERVICE_CONNECTION: 'health_service_access',
  BUSINESS_CONNECTION: 'business_registration',
  AGRICULTURAL_CONNECTION: 'agricultural_programme',
  DISPLACEMENT_CONNECTION: 'displacement_support',
  FORMER_RESIDENCY: 'historical_residence',
};
