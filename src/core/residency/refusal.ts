// SPDX-License-Identifier: Apache-2.0

/**
 * Refused applications, and the reference the applicant contests them with.
 *
 * Until this existed, a refusal persisted nothing. `issue()` returned
 * `{ status: 'rejected', reason }` and every rejection path returned before the only write, so
 * there was no record that the person had applied, no reason retained, and nowhere to appeal
 * to. The same defect ORCS §10 forbids for revocation -- a decision nobody can be held to --
 * one step earlier in the journey, and affecting people at the point of *entry* rather than
 * exit.
 *
 * It lands hardest on exactly the population a residency register exists to include. The
 * applicant whose evidence does not reach the required level is, by definition, the applicant
 * without documents.
 *
 * ## What is deliberately NOT stored
 *
 * A refusal record is not a database of people who failed verification. Building one would
 * mean retaining data about people this deployment could not verify, which is the opposite of
 * minimisation and would make the refusal log more sensitive than the register itself.
 *
 * So identity is recorded ONLY when the foundational check succeeded and produced a tokenized
 * `subjectRef`. When it did not -- an unknown number, a mistyped unit -- the record carries no
 * identifier at all: just the reference, the reason, the unit and who decided.
 *
 * The applicant is given the `reference`. Knowing it is what proves they were the one refused,
 * which is why it must be unguessable.
 */

export interface RefusalRecord {
  /** Opaque, unguessable. Handed to the applicant; the key they appeal with. */
  reference: string;
  countryCode: string;
  subnationalUnit: string;
  /**
   * The tokenized foundational reference, when verification got far enough to produce one.
   * Absent for refusals raised before an identity was established -- see the file header.
   */
  subjectRef?: string;
  /** The machine-readable reason `issue()` returned, e.g. PROOF_OF_RESIDENCE_REQUIRED. */
  reason: string;
  /**
   * What took the decision to refuse: an operator identity, or `automated:<policyVersion>`.
   *
   * In practice this is almost always automated. No path lets a person exercise judgement in
   * refusing -- the engine applies the jurisdiction's thresholds and the answer falls out --
   * so recording an operator here would misdescribe who is answerable for the outcome.
   */
  decidedBy: string;
  /**
   * The operator who took the application, kept separately.
   *
   * Distinct from `decidedBy` on purpose. The software decided, but a person was at the desk,
   * and losing that would leave nobody able to say where or by whom the application was
   * handled. Two facts, two fields, rather than one field meaning whichever the reader assumes.
   */
  submittedBy?: string;
  /** How the applicant contests it. Never blank -- see APPEAL_PATH_UNDECLARED. */
  appealPath: string;
  /**
   * Where the applicant obtains human review, set when the refusal was taken by software
   * alone. Absent when a person refused them -- they have already had the human.
   */
  humanReviewPath?: string;
  /** Whether a human has been asked to look again, and what they concluded. */
  reviewStatus: ReviewStatus;
  reviewedBy?: string;
  reviewedAt?: string;
  reviewNote?: string;
  refusedAt: string;
}

/**
 * The state of a request for human review.
 *
 * `overturned` exists because a review that cannot change the outcome is not a review. All
 * three regimes require the reviewer to hold genuine authority to reach a different answer,
 * so recording only "a human looked" would satisfy the letter and miss the point.
 */
export type ReviewStatus = 'none' | 'requested' | 'upheld' | 'overturned';

/** Persistence port, mirroring the other stores in this tree. */
export interface RefusalStore {
  save(record: RefusalRecord): Promise<RefusalRecord>;
  findByReference(reference: string): Promise<RefusalRecord | null>;
  /**
   * Refusals for one tokenized subject, most recent first.
   *
   * Only meaningful for refusals that got far enough to establish an identity. An operator
   * uses this to answer "has this person been refused before, and why" at the desk.
   */
  listBySubjectRef(subjectRef: string): Promise<RefusalRecord[]>;
  /** Record a review outcome against a refusal. Returns null if the reference is unknown. */
  recordReview(
    reference: string,
    review: { status: ReviewStatus; by: string; at: string; note?: string },
  ): Promise<RefusalRecord | null>;
}

/** In-memory implementation, for the smoke tests and single-node pilots. */
export class InMemoryRefusalStore implements RefusalStore {
  private byReference = new Map<string, RefusalRecord>();

  async save(record: RefusalRecord): Promise<RefusalRecord> {
    this.byReference.set(record.reference, record);
    return record;
  }
  async findByReference(reference: string): Promise<RefusalRecord | null> {
    return this.byReference.get(reference) ?? null;
  }
  async listBySubjectRef(subjectRef: string): Promise<RefusalRecord[]> {
    return [...this.byReference.values()]
      .filter((r) => r.subjectRef === subjectRef)
      .sort((a, b) => (a.refusedAt < b.refusedAt ? 1 : -1));
  }
  async recordReview(
    reference: string,
    review: { status: ReviewStatus; by: string; at: string; note?: string },
  ): Promise<RefusalRecord | null> {
    const existing = this.byReference.get(reference);
    if (!existing) return null;
    const updated: RefusalRecord = {
      ...existing,
      reviewStatus: review.status,
      reviewedBy: review.by,
      reviewedAt: review.at,
      reviewNote: review.note,
    };
    this.byReference.set(reference, updated);
    return updated;
  }
}

/**
 * Human-transcribable, unguessable.
 *
 * An applicant is handed this at a desk, often on paper, and may read it back over a phone.
 * Crockford's alphabet drops I, L, O and U, so it cannot be confused with 1/0 or read as a
 * word. 20 characters from a 32-symbol alphabet is 100 bits, which is far past guessing --
 * necessary because the reference is the only thing standing between a refusal record and
 * anyone who fancies reading somebody else's.
 */
const REFERENCE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateRefusalReference(randomBytes: (n: number) => Uint8Array): string {
  const bytes = randomBytes(20);
  let out = '';
  for (const b of bytes) out += REFERENCE_ALPHABET[b % REFERENCE_ALPHABET.length];
  return `REF-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}-${out.slice(16, 20)}`;
}