// SPDX-License-Identifier: Apache-2.0

/**
 * The breach register.
 *
 * A personal-data breach must be notified to the supervisory authority within a fixed number of
 * hours (72 in the jurisdictions this was written for) of the controller becoming aware of it, and to the affected people without delay where the risk to them is
 * high. The clock starts at detection, not at the decision to tell anyone, and the first thing
 * an investigator asks is when the controller knew. So the register records detection time
 * as its first field, computes the deadline from it, and is append-only: an entry is amended by
 * a later entry that references it, never edited, so the sequence of what was known when
 * survives. The register holds the description of the incident and counts; it never holds the
 * affected people's identifiers.
 */

import { breachDeadlines } from './compliance';

export type BreachCategory =
  | 'confidentiality'
  | 'integrity'
  | 'availability';

export interface BreachRecord {
  id: string;
  countryCode: string;
  /** When the controller became aware. The 72-hour clock runs from here. */
  detectedAt: string;
  /** When it was recorded here. */
  recordedAt: string;
  recordedBy: string;
  categories: BreachCategory[];
  description: string;
  /** Approximate number of people affected, where known. Never their identifiers. */
  subjectsAffected?: number;
  /** The controller's judgement that the risk to people is high. Drives subject notification. */
  highRisk: boolean;
  containment?: string;
  notifyAuthorityBy: string;
  notifySubjects: 'immediately' | 'not required unless risk rises';
  authorityNotifiedAt?: string;
  subjectsNotifiedAt?: string;
  /** An earlier entry this one amends or closes. */
  amends?: string;
}

export interface BreachStore {
  append(record: BreachRecord): Promise<void>;
  list(countryCode?: string): Promise<BreachRecord[]>;
}

export interface NewBreach {
  countryCode: string;
  detectedAt: string;
  recordedBy: string;
  categories: BreachCategory[];
  description: string;
  subjectsAffected?: number;
  highRisk: boolean;
  containment?: string;
  authorityNotifiedAt?: string;
  subjectsNotifiedAt?: string;
  amends?: string;
}

export function buildBreachRecord(
  input: NewBreach,
  id: string,
  nowIso = new Date().toISOString(),
  notificationHours = 72,
): BreachRecord {
  const deadlines = breachDeadlines(input.detectedAt, input.highRisk, notificationHours);
  const r: BreachRecord = {
    id,
    countryCode: input.countryCode,
    detectedAt: input.detectedAt,
    recordedAt: nowIso,
    recordedBy: input.recordedBy,
    categories: [...input.categories],
    description: input.description,
    highRisk: input.highRisk,
    notifyAuthorityBy: deadlines.notifyAuthorityBy,
    notifySubjects: deadlines.notifySubjects,
  };
  if (input.subjectsAffected != null) r.subjectsAffected = input.subjectsAffected;
  if (input.containment) r.containment = input.containment;
  if (input.authorityNotifiedAt) r.authorityNotifiedAt = input.authorityNotifiedAt;
  if (input.subjectsNotifiedAt) r.subjectsNotifiedAt = input.subjectsNotifiedAt;
  if (input.amends) r.amends = input.amends;
  return r;
}

export class InMemoryBreachStore implements BreachStore {
  private rows: BreachRecord[] = [];
  async append(record: BreachRecord): Promise<void> {
    this.rows.push({ ...record });
  }
  async list(countryCode?: string): Promise<BreachRecord[]> {
    const cc = countryCode?.toUpperCase();
    return this.rows
      .filter((r) => !cc || r.countryCode.toUpperCase() === cc)
      .sort((a, b) => a.recordedAt.localeCompare(b.recordedAt));
  }
}
