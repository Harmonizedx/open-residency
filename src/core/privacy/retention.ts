/**
 * Retention enforcement (DPG Standard indicator 7, ORCS §14).
 *
 * Keeping personal data longer than the purpose requires is itself a breach, so a register
 * that never forgets is not a safe one. This module decides WHAT is due; erasure decides what
 * "forgetting" means, and the two are deliberately separate — a policy that selects records
 * should not also be the thing that destroys them.
 *
 * Everything here is pure. The sweep that acts on these decisions lives in the delivery layer
 * where it can revoke credentials, redact audit entries and record what it did.
 */

/**
 * Retention periods for a deployment, in days, per record class.
 *
 * Per class on purpose. An audit entry, a consent grant and a residency record are kept under
 * different legal bases for different reasons; a single global number would be a policy that
 * fits none of them and would quietly destroy the audit trail that proves the other two were
 * handled correctly.
 *
 * `null` means "no automatic expiry". It is the shipped default for every class, and that is
 * deliberate: a retention period is a controller's decision against their own law, and a
 * default number here would be this software quietly setting policy for a government.
 */
export interface RetentionPolicy {
  /** Residency records, measured from `createdAt`. */
  residencyDays: number | null;
  /**
   * A hold that suspends every period.
   *
   * Litigation, an open appeal, or a regulator's request. The sweep refuses to run at all
   * while this is set, rather than reasoning about which records an appeal might implicate:
   * deleting the evidence an appeal turns on is the failure this exists to prevent, and a
   * partial sweep is a worse outcome than no sweep.
   */
  legalHold: boolean;
}

export const NO_AUTOMATIC_RETENTION: RetentionPolicy = {
  residencyDays: null,
  legalHold: false,
};

/** Has `createdAt` passed a period of `days`, as of `now`? */
export function isPastRetention(
  createdAt: string,
  days: number | null,
  now: Date = new Date(),
): boolean {
  if (days === null) return false;
  const created = Date.parse(createdAt);
  if (!Number.isFinite(created)) return false;
  return now.getTime() - created >= days * 86_400_000;
}

/** Why the sweep did nothing, when it does nothing. */
export type SweepSkipReason = 'legal-hold' | 'no-policy';

export interface RetentionSelection<T> {
  due: T[];
  /** Present when nothing was selected for a reason the operator needs to see. */
  skipped?: SweepSkipReason;
}

/**
 * Which residency records are due for erasure.
 *
 * Already-erased records are excluded, so a re-run is idempotent and does not churn rows it
 * has already dealt with. The two skip reasons are reported rather than returning an empty
 * list, because "nothing was due" and "the policy is switched off" look identical to a caller
 * otherwise, and an operator who thinks a sweep ran when it was held is badly misled.
 */
export function selectResidencyDue<T extends { createdAt: string; erasedAt?: string }>(
  records: T[],
  policy: RetentionPolicy,
  now: Date = new Date(),
): RetentionSelection<T> {
  if (policy.legalHold) return { due: [], skipped: 'legal-hold' };
  if (policy.residencyDays === null) return { due: [], skipped: 'no-policy' };
  return {
    due: records.filter((r) => !r.erasedAt && isPastRetention(r.createdAt, policy.residencyDays, now)),
  };
}