import { randomBytes } from 'node:crypto';

/**
 * Erasure and retention.
 *
 * DPG Standard indicator 7 requires a mechanism for deleting personal data. That obligation
 * and a tamper-evident register disagree with each other, and this module is where the
 * disagreement is resolved rather than dodged.
 *
 * Retention lived here too -- period-per-record-class, a legal hold, and the selection logic
 * for a sweep. It was removed because nothing in `src/` ever called it: no endpoint, no
 * service method, no scheduler. Tests exercised it, which made it look alive. Shipping a
 * retention policy a deployer has no way to run, while the DPG submission claimed running it
 * was "a deployment decision", was the same over-claim this repository has been correcting
 * elsewhere. It returns when there is something to run it.
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
