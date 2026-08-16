// SPDX-License-Identifier: Apache-2.0

/**
 * The credential's own lifecycle (ORCS §10), which is not the relationship's.
 *
 * `src/core/residency/lifecycle.ts` answers "does this person still hold residency here".
 * This answers "is this particular credential still usable". They move independently: a
 * credential can be suspended while the residency holds (a lost phone), and a residency can
 * end while an unexpired credential is still in a wallet. ADR-0007 separated the two acts;
 * this file gives the second one the record ORCS §10 requires of it.
 *
 * §10 states four requirements, and the third is the one that was missing entirely:
 *
 *   ISSUED -> ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED | EXPIRED | REPLACED
 *   Every credential MUST expose a machine-verifiable status reference.
 *   Revocation MUST preserve the reason, authority, timestamp and appeal path.
 *   Replacement MUST point to the superseding credential.
 *
 * Before this, `revoke()` flipped a bit in a bitstring and returned true. A cleared bit was
 * indistinguishable from one never set, nothing recorded who decided or why, and a citizen
 * whose credential was cancelled in error had nowhere to appeal to because no appeal path was
 * ever written down. "Revoked" was a fact about a bitstring rather than a decision anybody
 * could be held to.
 */

/** ORCS §10 credential states. */
export type CredentialStatus =
  | 'ISSUED'
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'EXPIRED'
  | 'REPLACED';

/** The states from which nothing moves on. */
const TERMINAL: CredentialStatus[] = ['REVOKED', 'EXPIRED', 'REPLACED'];

/**
 * ORCS §10's machine, exactly.
 *
 * ISSUED is distinct from ACTIVE because §10 lists it: a credential exists from the moment it
 * is minted, and becomes active when it is in the holder's possession. This implementation
 * issues and delivers in one step, so it records ACTIVE immediately -- but the state is kept
 * so a deployment with a collection step does not have to fork the vocabulary.
 */
const TRANSITIONS: Record<CredentialStatus, CredentialStatus[]> = {
  ISSUED: ['ACTIVE', 'REVOKED', 'EXPIRED', 'REPLACED'],
  ACTIVE: ['SUSPENDED', 'REVOKED', 'EXPIRED', 'REPLACED'],
  SUSPENDED: ['ACTIVE', 'REVOKED', 'EXPIRED', 'REPLACED'],
  REVOKED: [],
  EXPIRED: [],
  REPLACED: [],
};

export function isTerminalCredentialStatus(status: CredentialStatus): boolean {
  return TERMINAL.includes(status);
}

export function canTransitionCredential(from: CredentialStatus, to: CredentialStatus): boolean {
  return TRANSITIONS[from]?.includes(to) ?? false;
}

/** Which status list a state is published on. SUSPENDED is a separate bitstring from REVOKED. */
export type StatusPurpose = 'revocation' | 'suspension';

/**
 * What ORCS §10 requires be preserved about a status decision.
 *
 * `appealPath` is required for revocation specifically. A revocation a citizen cannot contest
 * is an administrative decision with no remedy attached, and for a statutory register that is
 * a legal problem before it is a conformance one. It is a string rather than a structured
 * object because what it points at differs by jurisdiction -- an office, a form, a statute
 * reference -- and inventing a schema for it here would constrain deployments for no gain.
 */
export interface CredentialStatusRecord {
  status: CredentialStatus;
  /** Why. Required for every terminal transition. */
  reason?: string;
  /** Who decided. An operator identity, never a bare "system". */
  authority?: string;
  /** When the decision was taken. */
  at?: string;
  /** How the holder contests it. Required for REVOKED (ORCS §10). */
  appealPath?: string;
  /** The credential that replaces this one. Required for REPLACED (ORCS §10). */
  supersededBy?: string;
}

export interface CredentialTransitionRequest {
  to: CredentialStatus;
  reason?: string;
  authority?: string;
  appealPath?: string;
  supersededBy?: string;
  at?: string;
}

export type CredentialTransitionOutcome =
  | { ok: true; record: CredentialStatusRecord; publish: { purpose: StatusPurpose; set: boolean }[] }
  | { ok: false; reason: string };

/**
 * Apply a credential status transition.
 *
 * Returns both the new record and which status-list bits must change, so a caller cannot
 * update one without the other. Keeping that pairing here rather than at each call site is
 * what stops a suspension being recorded but never published -- the failure mode where the
 * register believes a credential is suspended and every verifier still accepts it.
 */
export function applyCredentialTransition(
  current: CredentialStatusRecord,
  req: CredentialTransitionRequest,
): CredentialTransitionOutcome {
  if (!canTransitionCredential(current.status, req.to)) {
    return {
      ok: false,
      reason: isTerminalCredentialStatus(current.status)
        ? `CREDENTIAL_ALREADY_${current.status}`
        : `CREDENTIAL_TRANSITION_NOT_PERMITTED_${current.status}_TO_${req.to}`,
    };
  }

  // ORCS §10: revocation MUST preserve reason, authority, timestamp and appeal path. All four,
  // not three -- the appeal path is the one a system under delivery pressure drops first, and
  // it is the only one that exists for the citizen rather than for the operator.
  if (isTerminalCredentialStatus(req.to)) {
    if (!req.reason?.trim()) return { ok: false, reason: `REASON_REQUIRED_FOR_${req.to}` };
    if (!req.authority?.trim()) return { ok: false, reason: `AUTHORITY_REQUIRED_FOR_${req.to}` };
  }
  if (req.to === 'REVOKED' && !req.appealPath?.trim()) {
    return { ok: false, reason: 'APPEAL_PATH_REQUIRED_FOR_REVOCATION' };
  }
  if (req.to === 'REPLACED' && !req.supersededBy?.trim()) {
    return { ok: false, reason: 'SUPERSEDED_BY_REQUIRED_FOR_REPLACEMENT' };
  }
  if (req.to === 'SUSPENDED' && !req.authority?.trim()) {
    // Suspension is not terminal, but it still withdraws a credential from use, so it is held
    // to the same standard of attribution as ending one.
    return { ok: false, reason: 'AUTHORITY_REQUIRED_FOR_SUSPENDED' };
  }

  const at = req.at ?? new Date().toISOString();
  const record: CredentialStatusRecord = {
    status: req.to,
    at,
  };
  if (req.reason?.trim()) record.reason = req.reason.trim();
  if (req.authority?.trim()) record.authority = req.authority.trim();
  if (req.appealPath?.trim()) record.appealPath = req.appealPath.trim();
  if (req.supersededBy?.trim()) record.supersededBy = req.supersededBy.trim();

  // What the verifier must see. Reinstating clears the suspension bit; revoking sets the
  // revocation bit and clears any suspension, since a revoked credential should not also be
  // advertised as merely suspended.
  const publish: { purpose: StatusPurpose; set: boolean }[] = [];
  switch (req.to) {
    case 'SUSPENDED':
      publish.push({ purpose: 'suspension', set: true });
      break;
    case 'ACTIVE':
      publish.push({ purpose: 'suspension', set: false });
      break;
    case 'REVOKED':
    case 'REPLACED':
    case 'EXPIRED':
      publish.push({ purpose: 'revocation', set: true });
      publish.push({ purpose: 'suspension', set: false });
      break;
    default:
      break;
  }

  return { ok: true, record, publish };
}

/** A newly issued credential's status record. */
export function newCredentialStatus(at: string): CredentialStatusRecord {
  return { status: 'ACTIVE', at };
}

/**
 * The reading for a record written before this existed.
 *
 * An old row's credential was issued and, unless its revocation bit is set, was never
 * cancelled. The caller passes what the bitstring says, because that is the only evidence
 * those rows carry -- and it is exactly the ambiguity §10 exists to remove: a set bit tells
 * you the credential is dead and nothing about why or who decided.
 */
export function backfilledCredentialStatus(revokedBit: boolean, at: string): CredentialStatusRecord {
  if (!revokedBit) return { status: 'ACTIVE', at };
  return {
    status: 'REVOKED',
    at,
    reason: 'Revoked before the credential lifecycle recorded reasons; not recoverable',
    authority: 'migration:pre-lifecycle-record',
  };
}
