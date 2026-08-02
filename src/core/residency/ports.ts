import { StatusList } from '../credentials/status-list';
import { ApplicantBinding } from '../proofing/binding';
import { ResidenceAssuranceLevel, ResidenceEvidenceMethod } from '../proofing/residence';
import { DEFAULT_PURPOSE, RelationshipStatus, RelationshipType, relationshipKey } from './relationship';

/**
 * A residency record as persisted. Note: no raw national id is ever stored.
 *
 * ORCS §4.3 calls this a *jurisdictional relationship*: one person may hold several, each
 * with its own type, purpose, jurisdiction and lifecycle. The record is still named
 * `ResidentRecord` because it remains the compatibility surface every existing caller and
 * endpoint uses; the relationship fields below are what make several of them per person
 * legitimate rather than a duplicate to be reconciled away.
 */
export interface ResidentRecord {
  id: string; // internal uuid
  residentId: string; // human-facing id
  subjectRef: string; // tokenized foundational reference (per person+provider, NOT unique alone)
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  /**
   * ORCS §6.1 relationship type. Defaults to GENERAL_RESIDENCY, which is what every record
   * written before the relationship model existed implicitly was.
   */
  relationshipType: RelationshipType;
  /**
   * What this relationship is *for* (ORCS §4.3). Together with the jurisdiction it forms the
   * natural key: two relationships differing in purpose are distinct and may both be ACTIVE,
   * which is precisely what ORCS §7 means by "multiple relationships are normal".
   */
  purposeCode: string;
  /** ORCS §6.2 lifecycle state. Supersedes `provisional`, which is retained below for now. */
  status: RelationshipStatus;
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
   * The person's general residency, if they hold one.
   *
   * Deliberately narrower than it looks: a subjectRef now identifies a *person*, who may hold
   * several relationships, so "the record for this person" is no longer a well-formed
   * question. Callers wanting all of them use `listBySubjectRef`. This one answers the
   * question the enrolment path actually asks — "is this person already generally resident
   * here?" — and is scoped by jurisdiction and purpose for that reason.
   */
  findBySubjectRef(
    subjectRef: string,
    scope?: { subnationalUnit?: string; purposeCode?: string },
  ): Promise<ResidentRecord | null>;
  /** Every relationship held by a person, in any jurisdiction, at any status. */
  listBySubjectRef(subjectRef: string): Promise<ResidentRecord[]>;
  findByResidentId(residentId: string): Promise<ResidentRecord | null>;
  nextStatusIndex(countryCode: string): Promise<number>;
  save(record: ResidentRecord): Promise<ResidentRecord>;
  loadStatusList(countryCode: string): Promise<StatusList>;
  saveStatusList(countryCode: string, list: StatusList): Promise<void>;
  list(opts?: { countryCode?: string; limit?: number; offset?: number }): Promise<{
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

  async findBySubjectRef(
    subjectRef: string,
    scope?: { subnationalUnit?: string; purposeCode?: string },
  ): Promise<ResidentRecord | null> {
    const purposeCode = scope?.purposeCode ?? DEFAULT_PURPOSE.GENERAL_RESIDENCY;
    const held = await this.listBySubjectRef(subjectRef);
    return (
      held.find(
        (r) =>
          r.purposeCode === purposeCode &&
          (scope?.subnationalUnit === undefined || r.subnationalUnit === scope.subnationalUnit),
      ) ?? null
    );
  }
  async listBySubjectRef(subjectRef: string): Promise<ResidentRecord[]> {
    return [...this.residents.values()].filter((r) => r.subjectRef === subjectRef);
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
    // Keyed by (person, provider, jurisdiction, purpose), not by person alone. Keying on
    // subjectRef silently overwrote: saving a Kano employment relationship for someone who
    // already held a Katsina household one left a single row, so the in-memory store
    // disagreed with its own `list()` about how many relationships existed.
    this.residents.set(relationshipKey(record), record);
    this.byResidentId.set(record.residentId, record);
    return record;
  }
  async loadStatusList(countryCode: string): Promise<StatusList> {
    let list = this.statusLists.get(countryCode);
    if (!list) {
      list = new StatusList();
      this.statusLists.set(countryCode, list);
    }
    return list;
  }
  async saveStatusList(countryCode: string, list: StatusList): Promise<void> {
    this.statusLists.set(countryCode, list);
  }
  async list(opts?: { countryCode?: string; limit?: number; offset?: number }): Promise<{
    total: number;
    items: ResidentRecord[];
  }> {
    let items = [...this.byResidentId.values()];
    if (opts?.countryCode) items = items.filter((r) => r.countryCode === opts.countryCode);
    items.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    const total = items.length;
    const offset = opts?.offset ?? 0;
    const limit = opts?.limit ?? 50;
    return { total, items: items.slice(offset, offset + limit) };
  }
}
