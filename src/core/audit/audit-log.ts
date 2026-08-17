// SPDX-License-Identifier: Apache-2.0
import { createHash, randomBytes, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { JWK } from 'jose';
import { Signer } from '../credentials/signer';

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
  // A residency RELATIONSHIP changed state: ended, suspended, reinstated. Distinct from
  // residency.revoke, which is about a credential -- keeping the two audit actions apart is
  // what lets the trail say which act was intended (ADR-0007).
  | 'residency.relationship.transition'
  // A CREDENTIAL changed state under ORCS §10: suspended, reinstated, revoked, replaced.
  | 'residency.credential.transition'
  // A provisional record was checked against the live foundational authority. Recorded on
  // every outcome, not only success: a live match naming a DIFFERENT person is the entry an
  // investigator most needs to find, and it exists nowhere else.
  | 'residency.reconcile'
  // Provisional records revoked in bulk for never having been confirmed in the window.
  | 'residency.provisional.expire'
  // A person reconsidered a refusal the software took. NDPA s.37 / GDPR Art.22.
  | 'residency.refusal.review'
  | 'credential.verify'
  | 'consent.grant'
  | 'consent.revoke'
  // A lawful basis was withdrawn (ORCS §9). Every consent citing it stops authorising
  // processing from that moment, so the act needs its own trail entry rather than being
  // inferred from the consents that went quiet.
  | 'legalBasis.deactivate'
  | 'sso.login'
  // A resident was sent to an EXTERNAL OpenID Provider to authenticate, and came back.
  // Both halves are recorded: the start names the operator who began the enrolment, the
  // callback names none, because the resident's browser arrives there and attributing it
  // to staff who are not present would put a name in the trail that did not act.
  | 'sso.upstream.start'
  | 'sso.upstream.callback'
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

/**
 * A signed commitment to how long the chain was, and what its head was, at a moment.
 *
 * The hash chain proves that no event was edited, reordered or removed from the MIDDLE:
 * every such change breaks a link. It proves nothing about the END. Lopping off the last N
 * events leaves a shorter chain that verifies perfectly, because nothing recorded how long
 * the chain was supposed to be — and the most recent events are exactly the ones that
 * implicate whoever just got write access.
 *
 * A checkpoint closes that. It states "at this time there were `count` events and the head
 * was `hash` at `seq`", and it is SIGNED, so an attacker who can write to the database
 * cannot simply issue themselves a shorter one to match. Signing goes through the same
 * `Signer` port as credentials, so a deployment holding its issuer key in an HSM or KMS
 * anchors its audit log with a key it cannot export either.
 */
export interface AuditCheckpoint {
  /** Seq of the head event this checkpoint commits to. */
  seq: number;
  /** That event's hash. */
  hash: string;
  /** Total events at checkpoint time. Catches removal anywhere, not only at the tail. */
  count: number;
  createdAt: string;
  /** Base64url Ed25519 signature over `checkpointBytes`. */
  signature: string;
  /** Key that signed it, so a verifier can select from a rotated set. */
  kid: string;
}

export interface AuditCheckpointStore {
  put(checkpoint: AuditCheckpoint): Promise<void>;
  /** Most recent by seq. The one that binds the tail. */
  latest(): Promise<AuditCheckpoint | null>;
  all(): Promise<AuditCheckpoint[]>;
}

/**
 * Exactly the bytes a checkpoint signature covers.
 *
 * `signature` and `kid` are excluded — a signature cannot cover itself — and the field order
 * is fixed here rather than left to object insertion order, because a verifier that
 * serialises differently from the signer rejects every genuine checkpoint.
 */
export function checkpointBytes(
  cp: Pick<AuditCheckpoint, 'seq' | 'hash' | 'count' | 'createdAt'>,
): Uint8Array {
  const canonical = JSON.stringify({
    seq: cp.seq,
    hash: cp.hash,
    count: cp.count,
    createdAt: cp.createdAt,
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Does this checkpoint verify under any key we hold for the issuer?
 *
 * A list rather than one key for the same reason the credential trust list holds one: an
 * audit log outlives the key that anchored it, and a rotation must not retrospectively
 * invalidate every checkpoint signed before it.
 */
export async function verifyCheckpointSignature(
  cp: AuditCheckpoint,
  publicJwks: JWK[],
): Promise<boolean> {
  const data = Buffer.from(checkpointBytes(cp));
  const sig = Buffer.from(cp.signature, 'base64url');
  for (const jwk of publicJwks) {
    try {
      const key = createPublicKey({ key: jwk as object, format: 'jwk' });
      if (cryptoVerify(null, data, key, sig)) return true;
    } catch {
      // A malformed entry must not stop the good keys being tried.
    }
  }
  return false;
}

/** In-memory checkpoints, for tests and single-node pilots. */
export class InMemoryAuditCheckpointStore implements AuditCheckpointStore {
  private items: AuditCheckpoint[] = [];
  async put(checkpoint: AuditCheckpoint): Promise<void> {
    this.items.push(checkpoint);
  }
  async latest(): Promise<AuditCheckpoint | null> {
    if (!this.items.length) return null;
    return this.items.reduce((a, b) => (b.seq >= a.seq ? b : a));
  }
  async all(): Promise<AuditCheckpoint[]> {
    return this.items.slice();
  }
}

export class AuditLog {
  /**
   * `checkpoints` and `signer` are optional so every existing construction keeps working and
   * a deployment without an anchor degrades to exactly the previous behaviour — reported as
   * `anchored: false` rather than silently passing as though the tail were protected.
   */
  constructor(
    private store: AuditStore,
    private checkpoints?: AuditCheckpointStore,
    private signer?: Signer,
  ) {}

  /**
   * Commit to the current head, and sign it.
   *
   * Called on a schedule. The window between checkpoints is the window in which a tail can
   * still be dropped undetected, so the interval is a deployment's choice about how much
   * exposure it accepts — not something to infer here.
   *
   * Returns null when the log is empty or no anchor is configured: there is nothing to
   * commit to, and writing a checkpoint over an empty chain would assert a fact about
   * nothing.
   */
  async checkpoint(): Promise<AuditCheckpoint | null> {
    if (!this.checkpoints || !this.signer) return null;
    const tail = await this.store.tail();
    if (!tail) return null;
    const count = (await this.store.all()).length;

    const unsigned = {
      seq: tail.seq,
      hash: tail.hash,
      count,
      createdAt: new Date().toISOString(),
    };
    const signature = await this.signer.sign(checkpointBytes(unsigned));
    const cp: AuditCheckpoint = {
      ...unsigned,
      signature: Buffer.from(signature).toString('base64url'),
      kid: this.signer.kid,
    };
    await this.checkpoints.put(cp);
    return cp;
  }

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
  async verifyChain(opts: { publicJwks?: JWK[] } = {}): Promise<{
    ok: boolean;
    length: number;
    redacted: number;
    brokenAtSeq?: number;
    /** Whether a signed checkpoint was available to bind the tail. */
    anchored: boolean;
    checkpoints: number;
    /** Set when a checkpoint proves events after this seq were removed. */
    truncatedAfterSeq?: number;
    /** Set when the anchor itself could not be trusted. */
    anchorProblem?: 'unsigned' | 'untrusted' | 'no-checkpoint';
  }> {
    const events = await this.store.all();
    let prevHash = GENESIS;
    let redacted = 0;
    for (const e of events) {
      if (e.prevHash !== prevHash) {
        return {
          ok: false,
          length: events.length,
          redacted,
          brokenAtSeq: e.seq,
          anchored: false,
          checkpoints: 0,
        };
      }
      if (e.redactedAt) {
        redacted++;
      } else if (e.hash !== hashEvent({ ...e })) {
        return {
          ok: false,
          length: events.length,
          redacted,
          brokenAtSeq: e.seq,
          anchored: false,
          checkpoints: 0,
        };
      }
      prevHash = e.hash;
    }

    // The links are intact. That says nothing about the END of the chain, which is what the
    // anchor is for.
    const all = (await this.checkpoints?.all()) ?? [];
    const base = { length: events.length, redacted, checkpoints: all.length };
    if (!all.length) {
      // Reported, never treated as success. A chain with no anchor is exactly as truncatable
      // as it was before checkpoints existed, and an auditor is entitled to be told so
      // rather than shown a green tick that does not cover the tail.
      return { ...base, ok: true, anchored: false, anchorProblem: 'no-checkpoint' };
    }

    const latest = all.reduce((a, b) => (b.seq >= a.seq ? b : a));

    // Authenticate the checkpoint BEFORE believing it. An attacker who can delete events can
    // usually also write a shorter checkpoint; the signature is the only thing they cannot
    // produce, so an unverifiable anchor must not be read as agreement.
    if (opts.publicJwks?.length) {
      const trusted = await verifyCheckpointSignature(latest, opts.publicJwks);
      if (!trusted) {
        return { ...base, ok: false, anchored: false, anchorProblem: 'untrusted' };
      }
    } else {
      return { ...base, ok: true, anchored: false, anchorProblem: 'unsigned' };
    }

    const atSeq = events.find((e) => e.seq === latest.seq);
    if (!atSeq) {
      // The checkpoint commits to an event the chain no longer contains: the tail was cut.
      return {
        ...base,
        ok: false,
        anchored: true,
        truncatedAfterSeq: events.length ? events[events.length - 1].seq : -1,
      };
    }
    if (atSeq.hash !== latest.hash) {
      return { ...base, ok: false, anchored: true, brokenAtSeq: latest.seq };
    }
    if (events.length < latest.count) {
      // Same head, fewer events: something was removed from the middle and the links were
      // rebuilt around the gap.
      return { ...base, ok: false, anchored: true, truncatedAfterSeq: latest.seq };
    }

    return { ...base, ok: true, anchored: true };
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
  // 12 bytes from the CSPRNG, hex-encoded to the same 24 characters this has always
  // produced. The previous construction hashed Date.now(), Math.random() and hrtime:
  // the output looked random, but Math.random() is not a cryptographic generator, so
  // the entropy was whatever the clock and a predictable PRNG supplied. Nothing here
  // depends on these ids being unguessable -- chain integrity rests on the SHA-256
  // hash, not the id -- but a function named cryptoRandomId must not be the one place
  // a reader has to check that claim.
  return randomBytes(12).toString('hex');
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
