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
  // A resident enrolled a WebAuthn passkey (authorized by an existing factor).
  | 'webauthn.register'
  | 'admin.read'
  // OpenID4VCI: a credential offer was created for a resident, and a wallet redeemed it.
  | 'oid4vci.offer.create'
  | 'oid4vci.credential.issue'
  // OpenID4VP: a relying party asked for a presentation, and a wallet answered.
  | 'oid4vp.request.create'
  | 'oid4vp.presentation.verify'
  // Operator identity: staff sign-in, account changes, and the lifecycle of the API keys
  // machine callers authenticate with. These are audited for the same reason residency
  // actions are -- a privileged action nobody can be held to is not controlled.
  | 'operator.login'
  | 'operator.create'
  | 'operator.disable'
  | 'operator.enable'
  | 'operator.key.create'
  | 'operator.key.rotate'
  | 'operator.key.revoke'
  | 'audit.redact'
  | 'resident.erase';

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
  /**
   * Set when this event's personal data has been redacted under an erasure request.
   *
   * The event is not deleted and the chain is not rewritten. `hash` still commits to the
   * ORIGINAL content, so anyone holding an earlier copy of the log can prove what this event
   * said; what is gone is the plaintext.
   */
  redactedAt?: string;
}

/** The value substituted for a redacted field, so a reader sees absence, not emptiness. */
export const REDACTED = '[redacted]';

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
  /** Overwrite an existing event in place. Used only by redaction, never by `record`. */
  replace(event: AuditEvent): Promise<void>;
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

  /**
   * Recompute the chain and report the first break, if any.
   *
   * A redacted event cannot have its hash recomputed -- the content it committed to is gone,
   * which is the point of erasure. Its LINK is still checked (its `prevHash` must match the
   * previous event's hash, and the next event chains onto its stored hash), so a redacted
   * event cannot be removed, reordered, or inserted without breaking the chain either side
   * of it. What redaction costs is the ability to re-derive that one event's hash from its
   * own content; what it does not cost is the integrity of the sequence.
   *
   * `redacted` is returned rather than hidden. An auditor is entitled to know that the log
   * they are verifying has had material removed, and how much.
   */
  async verifyChain(): Promise<{
    ok: boolean;
    length: number;
    redacted: number;
    brokenAtSeq?: number;
  }> {
    const events = await this.store.all();
    let prevHash = GENESIS;
    let redacted = 0;
    for (const e of events) {
      if (e.prevHash !== prevHash) {
        return { ok: false, length: events.length, redacted, brokenAtSeq: e.seq };
      }
      if (e.redactedAt) {
        redacted++;
      } else if (e.hash !== hashEvent({ ...e })) {
        return { ok: false, length: events.length, redacted, brokenAtSeq: e.seq };
      }
      prevHash = e.hash;
    }
    return { ok: true, length: events.length, redacted };
  }

  /**
   * Redact the personal data in one event, and record that this happened.
   *
   * Erasure and a tamper-evident log pull in opposite directions: the citizen has a right to
   * have their data removed, and the register has an obligation to show that nothing was
   * quietly rewritten. Deleting the row satisfies the first and destroys the second.
   *
   * So the row stays, its personal fields are replaced, its original hash is kept as the
   * commitment to what it used to say, and the redaction is itself appended as a new chained
   * event naming who did it and under what authority. A redaction cannot be performed
   * silently: removing the record of it breaks the chain exactly as tampering would.
   */
  async redact(
    seq: number,
    by: { actor: string; reason: string; legalBasis?: string },
  ): Promise<AuditEvent | null> {
    const target = (await this.store.all()).find((e) => e.seq === seq);
    if (!target || target.redactedAt) return target ?? null;

    const redacted: AuditEvent = {
      ...target,
      actor: REDACTED,
      target: target.target ? REDACTED : undefined,
      metadata: undefined,
      redactedAt: new Date().toISOString(),
      // `hash` and `prevHash` are deliberately untouched.
    };
    await this.store.replace(redacted);

    await this.record({
      action: 'audit.redact',
      actor: by.actor,
      target: String(seq),
      outcome: 'success',
      metadata: { reason: by.reason, legalBasis: by.legalBasis ?? null, redactedSeq: seq },
    });
    return redacted;
  }

  /** Redact every event naming `subject`, for an erasure request. Returns the seqs redacted. */
  async redactSubject(
    subject: string,
    by: { actor: string; reason: string; legalBasis?: string },
  ): Promise<number[]> {
    const events = await this.store.all();
    const seqs = events
      .filter((e) => !e.redactedAt && (e.target === subject || e.actor === subject))
      .map((e) => e.seq);
    for (const seq of seqs) await this.redact(seq, by);
    return seqs;
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
  async replace(event: AuditEvent): Promise<void> {
    const i = this.events.findIndex((e) => e.seq === event.seq);
    if (i >= 0) this.events[i] = event;
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
