import { StatusList } from '../credentials/status-list';
import { ApplicantBinding } from '../proofing/binding';

/** A residency record as persisted. Note: no raw national id is ever stored. */
export interface ResidentRecord {
  id: string; // internal uuid
  residentId: string; // human-facing id
  subjectRef: string; // tokenized foundational reference (unique per person+provider)
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  /** How the applicant was proven to own this identity at enrolment. */
  binding: ApplicantBinding;
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
  findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null>;
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

  async findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null> {
    return this.residents.get(subjectRef) ?? null;
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
    this.residents.set(record.subjectRef, record);
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
