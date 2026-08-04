import { randomBytes } from 'node:crypto';
import { ResidentRecord } from '../residency/ports';

/**
 * Erasure and retention.
 *
 * DPG Standard indicator 7 requires a mechanism for deleting personal data and a documented
 * retention position; ORCS §14 requires retention enforcement and a resident-visible audit
 * history. Those two obligations disagree with each other, and this module is where the
 * disagreement is resolved rather than dodged.
 *
 * A tamper-evident register cannot simply delete rows, because "the log cannot be quietly
 * altered" is precisely what deleting rows breaks. But a citizen's right to erasure is not
 * satisfied by a system that answers "we keep everything for integrity reasons".
 *
 * The resolution is that erasure removes the person, not the record of the transaction:
 *
 *   - Everything identifying is destroyed: names, date of birth, gender, contact details,
 *     and the tokenized `subjectRef` that links this record to a foundational identity.
 *   - A hollow row remains, carrying `residentId`, `statusListIndex` and `erasedAt`.
 *   - The credential is revoked first, so what is left cannot be used.
 *
 * The row is kept for three specific reasons, each of which would be a defect if it were
 * dropped:
 *
 *   1. `statusListIndex` must never be reused. Reissuing an erased person's index to a new
 *      resident would make the new resident's credential inherit the old revocation bit.
 *   2. The credential must stay revoked. A revocation whose record is deleted is a
 *      revocation that can be forgotten.
 *   3. `residentId` appears in audit events that are chained. Erasing it there is redaction
 *      (see AuditLog.redact), not deletion, for the same integrity reason.
 *
 * What remains is not personal data in any useful sense: an opaque identifier with no name,
 * no contact, no link to a national ID, and a revoked credential. A deployment that wants
 * the row gone entirely can delete it once its retention period has expired AND the status
 * list has been rotated -- that is a deliberate, documented operation, not a default.
 */

/** Every field on a resident record that identifies a person, in one place. */
export const IDENTIFYING_FIELDS = [
  'subjectRef',
  'fullName',
  'givenName',
  'familyName',
  'dateOfBirth',
  'gender',
  'phoneHash',
  'phoneEnc',
] as const;

/**
 * The tombstone written over `subjectRef`.
 *
 * Not null and not a constant: the column is unique and NOT NULL, and a shared constant
 * would collide on the second erasure. A random tombstone also means an erased record can
 * never again match a foundational lookup, so the same person re-enrolling is correctly
 * treated as new rather than found and resurrected.
 */
export function erasureTombstone(): string {
  return `erased:${randomBytes(16).toString('hex')}`;
}

/** A resident record with every identifying field removed. */
export type ErasedResident = Omit<ResidentRecord, 'person'> & {
  person: Record<string, never>;
  erasedAt: string;
};

export function eraseRecord(record: ResidentRecord, at: Date = new Date()): ErasedResident {
  return {
    ...record,
    subjectRef: erasureTombstone(),
    person: {},
    erasedAt: at.toISOString(),
  };
}

/**
 * Retention policy for a deployment.
 *
 * Periods are stated in days and are deliberately per record class: an audit entry, a
 * consent grant and a residency record are kept under different legal bases and for
 * different reasons, so one global number would be a policy that fits none of them.
 *
 * `null` means "no automatic expiry" and must be a deliberate choice, not a default that
 * arose because nobody set a number.
 */
export interface RetentionPolicy {
  /** Residency records, measured from `createdAt`. */
  residencyDays: number | null;
  /** Consent records, measured from grant. Withdrawal does not shorten this: proof that
   *  consent was given and withdrawn is itself a record the deployer may need to keep. */
  consentDays: number | null;
  /** Audit events, measured from the event timestamp. */
  auditDays: number | null;
  /**
   * A hold that suspends every period above.
   *
   * Litigation, an open appeal, or a regulator's request. Retention deletion that ignores an
   * appeal in progress destroys the evidence the appeal turns on, so the sweep refuses to
   * run at all while this is set rather than trying to reason about which records are
   * implicated.
   */
  legalHold?: boolean;
}

export const NO_AUTOMATIC_RETENTION: RetentionPolicy = {
  residencyDays: null,
  consentDays: null,
  auditDays: null,
};

/** Has `createdAt` passed the retention period, as of `now`? */
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

/**
 * Which residency records are due for erasure under this policy.
 *
 * Already-erased records are excluded, so a sweep is idempotent and does not churn rows it
 * has already dealt with.
 */
export function residencyDueForErasure<T extends { createdAt: string; erasedAt?: string }>(
  records: T[],
  policy: RetentionPolicy,
  now: Date = new Date(),
): T[] {
  if (policy.legalHold) return [];
  return records.filter((r) => !r.erasedAt && isPastRetention(r.createdAt, policy.residencyDays, now));
}