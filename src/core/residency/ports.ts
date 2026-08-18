// SPDX-License-Identifier: Apache-2.0
import { StatusList } from '../credentials/status-list';
import { ResidentId } from '../kernel/branded';
import { RelationshipAttributes } from './lifecycle';
import { CredentialStatusRecord, StatusPurpose } from '../credentials/credential-lifecycle';
import { ApplicantBinding } from '../proofing/binding';
import { ResidenceAssuranceLevel, ResidenceEvidenceMethod } from '../proofing/residence';

/**
 * A residency record as persisted. Note: no raw national id is ever stored.
 *
 * One per person, in this deployment. A deployment is a single subnational government, so
 * "this person's residency" is a well-formed question with one answer. Their connections to
 * other jurisdictions belong to those jurisdictions and arrive here as credentials to
 * verify, never as records to hold.
 */
export interface ResidentRecord {
  id: string; // internal uuid
  residentId: ResidentId; // human-facing id, branded so it cannot be swapped for another
  subjectRef: string; // tokenized foundational reference (unique per person+provider)
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  /** How the applicant was proven to own this identity at enrolment. */
  binding: ApplicantBinding;
  /** The proof-of-residence achieved for this resident in their claimed unit. */
  residence: {
    assuranceLevel: ResidenceAssuranceLevel;
    method: ResidenceEvidenceMethod;
    unit?: string;
    asOf?: string;
  };
  provisional: boolean;
  /**
   * The ORCS §4.3 attributes this relationship states about itself: status, validity, type,
   * purpose, policy version, evidence references, assurance profile, issuer and decision
   * provenance. Jurisdiction is `countryCode` + `subnationalUnit` above.
   *
   * Optional on the type because ADR-0006 keeps this additive: a row written before the
   * lifecycle existed has none, and is read as ACTIVE with backfilled provenance rather than
   * rejected. New records always carry it.
   */
  relationship?: RelationshipAttributes;
  /**
   * The credential's own ORCS §10 status: why it was revoked or suspended, by whom, when, and
   * how the holder contests it. Distinct from `relationship` above -- one is about a key, the
   * other about a person's standing in the jurisdiction.
   *
   * Optional for the same additive reason: a row written before this reads through
   * `backfilledCredentialStatus` from whatever its revocation bit says.
   */
  credentialStatus?: CredentialStatusRecord;
  /** Set when this resident's identifying data was erased. See core/privacy/erasure.ts. */
  erasedAt?: string;
  credentialId?: string;
  statusListIndex: number;
  createdAt: string;
  person: {
    fullName?: string;
    givenName?: string;
    familyName?: string;
    dateOfBirth?: string;
    gender?: string;
  };
}

/**
 * Persistence port. Implementations: InMemoryStore (tests/pilots) and a Prisma-backed
 * store (production). Keeping this an interface is what lets the same residency logic
 * run in a CI smoke test and against PostgreSQL unchanged.
 */
export interface ResidencyStore {
  /**
   * This person's residency in this deployment, if they hold one.
   *
   * At most one: a deployment is a single subnational government, and `subjectRef` is unique.
   * A person's relationships with OTHER jurisdictions live in those jurisdictions' own
   * deployments and are seen here only as credentials to verify, never as rows.
   */
  findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null>;
  /**
   * Destroy every identifying field on a record, in place, keeping the hollow row.
   *
   * `tombstone` replaces `subjectRef`: the column is unique and NOT NULL, so erasure needs a
   * value that cannot collide with another erased row and cannot match a future foundational
   * lookup. Returns null if the resident is unknown.
   */
  erase(residentId: ResidentId, tombstone: string, at: Date): Promise<ResidentRecord | null>;
  findByResidentId(residentId: ResidentId): Promise<ResidentRecord | null>;
  nextStatusIndex(countryCode: string): Promise<number>;
  save(record: ResidentRecord): Promise<ResidentRecord>;
  /**
   * The status list for a jurisdiction and purpose.
   *
   * Two lists, not one: ORCS §10 distinguishes SUSPENDED from REVOKED, and a verifier has to
   * be able to tell them apart. `purpose` defaults to 'revocation' so every existing caller
   * and stored row keeps its meaning.
   */
  loadStatusList(countryCode: string, purpose?: StatusPurpose): Promise<StatusList>;
  saveStatusList(countryCode: string, list: StatusList, purpose?: StatusPurpose): Promise<void>;
  /**
   * Page the register.
   *
   * `provisional` filters on the flag rather than adding a second listing method: the
   * reconciliation sweep needs exactly "the provisional ones", and a caller that wants
   * everything simply omits it.
   */
  list(opts?: {
    countryCode?: string;
    limit?: number;
    offset?: number;
    provisional?: boolean;
  }): Promise<{
    total: number;
    items: ResidentRecord[];
  }>;
}

/** Simple in-memory implementation for demos, pilots, and tests. */
export class InMemoryStore implements ResidencyStore {
  private residents = new Map<string, ResidentRecord>();
  private byResidentId = new Map<string, ResidentRecord>();
  private counters = new Map<string, number>();
  private statusLists = new Map<string, StatusList>();

  async findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null> {
    return this.residents.get(subjectRef) ?? null;
  }
  async erase(residentId: string, tombstone: string, at: Date): Promise<ResidentRecord | null> {
    const existing = this.byResidentId.get(residentId);
    if (!existing) return null;
    // Drop the old subjectRef key too, or a lookup by the pre-erasure reference still finds
    // the record and the erasure is cosmetic.
    this.residents.delete(existing.subjectRef);
    const erased: ResidentRecord = {
      ...existing,
      subjectRef: tombstone,
      person: {},
      erasedAt: at.toISOString(),
    };
    this.residents.set(tombstone, erased);
    this.byResidentId.set(residentId, erased);
    return erased;
  }
  async findByResidentId(residentId: string): Promise<ResidentRecord | null> {
    return this.byResidentId.get(residentId) ?? null;
  }
  async nextStatusIndex(countryCode: string): Promise<number> {
    const n = this.counters.get(countryCode) ?? 0;
    this.counters.set(countryCode, n + 1);
    return n;
  }
  async save(record: ResidentRecord): Promise<ResidentRecord> {
    // Keyed by subjectRef, matching the `@unique` constraint in Prisma. One person, one
    // residency, in this deployment. If these two ever diverge the in-memory store will
    // accept enrolments PostgreSQL rejects, and the smoke suites will stop predicting
    // production -- which is the only reason this store is worth having.
    this.residents.set(record.subjectRef, record);
    this.byResidentId.set(record.residentId, record);
    return record;
  }
  async loadStatusList(
    countryCode: string,
    purpose: StatusPurpose = 'revocation',
  ): Promise<StatusList> {
    const key = `${countryCode}:${purpose}`;
    let list = this.statusLists.get(key);
    if (!list) {
      list = new StatusList();
      this.statusLists.set(key, list);
    }
    return list;
  }
  async saveStatusList(
    countryCode: string,
    list: StatusList,
    purpose: StatusPurpose = 'revocation',
  ): Promise<void> {
    this.statusLists.set(`${countryCode}:${purpose}`, list);
  }
  async list(opts?: {
    countryCode?: string;
    limit?: number;
    offset?: number;
    provisional?: boolean;
  }): Promise<{
    total: number;
    items: ResidentRecord[];
  }> {
    let items = [...this.byResidentId.values()];
    if (opts?.countryCode) items = items.filter((r) => r.countryCode === opts.countryCode);
    if (opts?.provisional !== undefined) {
      items = items.filter((r) => r.provisional === opts.provisional);
    }
    items.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    const total = items.length;
    const offset = opts?.offset ?? 0;
    const limit = opts?.limit ?? 50;
    return { total, items: items.slice(offset, offset + limit) };
  }
}
