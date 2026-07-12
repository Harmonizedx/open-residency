import { createHash } from 'node:crypto';

/**
 * Tamper-evident audit log.
 *
 * Every event is chained to the previous one with a SHA-256 hash, so any later
 * edit or deletion breaks the chain and is detectable. This is the property a
 * public-infrastructure auditor asks for: not just "we log", but "the log cannot
 * be quietly altered after the fact".
 *
 * The log is deliberately privacy-preserving. It records WHAT happened to WHICH
 * residency (by residentId or tokenized subjectRef), never the raw national ID.
 */

export type AuditAction =
  | 'identity.verify'
  | 'identity.challenge'
  | 'residency.issue'
  | 'residency.revoke'
  | 'credential.verify'
  | 'consent.grant'
  | 'consent.revoke'
  | 'sso.login'
  | 'admin.read';

export interface AuditEventInput {
  action: AuditAction;
  actor: string; // who caused it: 'citizen', 'system', an admin id, a client_id
  target?: string; // residentId, consent id, client id, etc.
  countryCode?: string;
  outcome: 'success' | 'failure';
  /** Non-sensitive context. Never put raw national IDs or OTPs here. */
  metadata?: Record<string, unknown>;
}

export interface AuditEvent extends AuditEventInput {
  seq: number;
  id: string;
  timestamp: string;
  prevHash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

export function hashEvent(e: Omit<AuditEvent, 'hash'>): string {
  // Canonical, stable serialization of the fields that are chained.
  const canonical = JSON.stringify({
    seq: e.seq,
    id: e.id,
    timestamp: e.timestamp,
    action: e.action,
    actor: e.actor,
    target: e.target ?? null,
    countryCode: e.countryCode ?? null,
    outcome: e.outcome,
    metadata: e.metadata ?? null,
    prevHash: e.prevHash,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

export interface AuditStore {
  append(event: AuditEvent): Promise<void>;
  tail(): Promise<{ seq: number; hash: string } | null>;
  list(opts?: { limit?: number; offset?: number; target?: string }): Promise<AuditEvent[]>;
  all(): Promise<AuditEvent[]>;
}

export class AuditLog {
  constructor(private store: AuditStore) {}

  async record(input: AuditEventInput): Promise<AuditEvent> {
    const tail = await this.store.tail();
    const seq = (tail?.seq ?? -1) + 1;
    const prevHash = tail?.hash ?? GENESIS;
    const base: Omit<AuditEvent, 'hash'> = {
      ...input,
      seq,
      id: cryptoRandomId(),
      timestamp: new Date().toISOString(),
      prevHash,
    };
    const event: AuditEvent = { ...base, hash: hashEvent(base) };
    await this.store.append(event);
    return event;
  }

  list(opts?: { limit?: number; offset?: number; target?: string }) {
    return this.store.list(opts);
  }

  /** Recompute the chain and report the first break, if any. */
  async verifyChain(): Promise<{ ok: boolean; length: number; brokenAtSeq?: number }> {
    const events = await this.store.all();
    let prevHash = GENESIS;
    for (const e of events) {
      const expected = hashEvent({ ...e });
      if (e.prevHash !== prevHash || e.hash !== expected) {
        return { ok: false, length: events.length, brokenAtSeq: e.seq };
      }
      prevHash = e.hash;
    }
    return { ok: true, length: events.length };
  }
}

function cryptoRandomId(): string {
  return createHash('sha256')
    .update(`${Date.now()}:${Math.random()}:${process.hrtime.bigint()}`)
    .digest('hex')
    .slice(0, 24);
}

/** In-memory store for tests, pilots, and CI. */
export class InMemoryAuditStore implements AuditStore {
  private events: AuditEvent[] = [];
  async append(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }
  async tail(): Promise<{ seq: number; hash: string } | null> {
    const last = this.events[this.events.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : null;
  }
  async list(opts?: { limit?: number; offset?: number; target?: string }): Promise<AuditEvent[]> {
    let out = this.events;
    if (opts?.target) out = out.filter((e) => e.target === opts.target);
    const offset = opts?.offset ?? 0;
    const limit = opts?.limit ?? 100;
    return out.slice().reverse().slice(offset, offset + limit);
  }
  async all(): Promise<AuditEvent[]> {
    return this.events.slice();
  }
}
