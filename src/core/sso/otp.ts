// SPDX-License-Identifier: Apache-2.0
import { createHash, randomInt, timingSafeEqual } from 'node:crypto';

/**
 * One-time-code authentication for the residency IdP.
 *
 * This is the fallback sign-in factor, for a citizen whose wallet is not to hand. The
 * strong factor is a Verifiable Presentation (see sso-auth.ts); this exists so that not
 * owning a smartphone at the moment of sign-in does not lock someone out -- an inclusion
 * requirement, not an afterthought.
 *
 * A deliberate privacy boundary runs through here. OpenResidency does not store plaintext
 * phone numbers -- the schema keeps only a phoneHash, and the whole tokenization design
 * exists to avoid holding contact PII. So this service never sees a phone number. It
 * generates and checks the code; DELIVERING it is delegated to an OtpSender. The real
 * implementation lives in core/messaging: a configured aggregator plus a contact directory
 * that resolves a residentId to a number at send time.
 *
 * The code lifecycle is the security-critical part, and it is fully real:
 *   - codes are random, and stored only as a hash;
 *   - a code verifies at most once (consumed on success);
 *   - codes expire;
 *   - wrong guesses are counted, and the challenge locks -- a 6-digit code is only safe
 *     if the number of attempts against it is bounded;
 *   - and that bound is CUMULATIVE PER RESIDENT, not per challenge. Locking only the
 *     challenge would be no bound at all: requesting a new code resets the counter, so an
 *     attacker alternating "send me a code" with five guesses gets unlimited attempts at
 *     a 10^-6 target, and the resident pays for it in delivered messages. Both the guesses
 *     and the sends are therefore counted over a rolling window against the residentId.
 */

export interface OtpChallengeRecord {
  id: string;
  residentId: string;
  codeHash: string;
  channel: string;
  expiresAt: string;
  consumed: boolean;
  failedAttempts: number;
  createdAt: string;
}

export interface OtpStore {
  save(challenge: OtpChallengeRecord): Promise<void>;
  /** The most recent unconsumed challenge for a resident, if any. */
  findActive(residentId: string): Promise<OtpChallengeRecord | null>;
  update(challenge: OtpChallengeRecord): Promise<void>;
  /**
   * Every challenge created for this resident at or after `since`, consumed or not.
   *
   * This is what makes the per-resident bound possible without new state: the rows
   * already carry `failedAttempts` and `createdAt`, so the window can be summed from
   * them and no migration is needed.
   */
  recentFor(residentId: string, since: string): Promise<OtpChallengeRecord[]>;
}

/** In-memory OTP store for tests and single-node pilots. */
export class InMemoryOtpStore implements OtpStore {
  private byId = new Map<string, OtpChallengeRecord>();

  async save(challenge: OtpChallengeRecord): Promise<void> {
    this.byId.set(challenge.id, { ...challenge });
  }
  async findActive(residentId: string): Promise<OtpChallengeRecord | null> {
    const active = [...this.byId.values()]
      .filter((c) => c.residentId === residentId && !c.consumed)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return active[0] ? { ...active[0] } : null;
  }
  async update(challenge: OtpChallengeRecord): Promise<void> {
    this.byId.set(challenge.id, { ...challenge });
  }
  async recentFor(residentId: string, since: string): Promise<OtpChallengeRecord[]> {
    // ISO-8601 UTC strings sort lexicographically in time order, so a string compare is
    // a date compare here.
    return [...this.byId.values()]
      .filter((c) => c.residentId === residentId && c.createdAt >= since)
      .map((c) => ({ ...c }));
  }
}

/**
 * Delivers a one-time code to the resident. Implemented by the deployment against its own
 * SMS/USSD gateway and contact directory -- which is what keeps plaintext phone numbers
 * out of OpenResidency's own store.
 */
export interface OtpSender {
  /** Deliver `code` to the resident identified by `residentId`. Returns the channel used. */
  send(residentId: string, code: string): Promise<{ channel: string }>;
}

export interface OtpLimits {
  /** How long a delivered code stays valid. */
  ttlSeconds: number;
  /** Wrong guesses allowed against one challenge before it stops accepting any. */
  maxAttemptsPerChallenge: number;
  /** The rolling window over which the two per-resident bounds below are counted. */
  windowSeconds: number;
  /**
   * Wrong guesses allowed per resident per window, summed across every challenge.
   *
   * This is the bound that actually protects a 6-digit code, because it is the one an
   * attacker cannot reset by asking for another code.
   */
  maxAttemptsPerWindow: number;
  /**
   * Codes a resident may be sent per window.
   *
   * Two jobs: it caps how many fresh targets an attacker can generate, and it caps what
   * an attacker can spend of the deployment's messaging budget -- every issue is a real
   * SMS to a real person who did not ask for it.
   */
  maxChallengesPerWindow: number;
}

export const DEFAULT_OTP_LIMITS: OtpLimits = {
  ttlSeconds: 5 * 60,
  maxAttemptsPerChallenge: 5,
  windowSeconds: 60 * 60,
  maxAttemptsPerWindow: 10,
  maxChallengesPerWindow: 5,
};

/**
 * Raised when a resident has exhausted their issuance budget for the window.
 *
 * Distinct from a delivery failure so a caller can tell "we would not send" from "we
 * tried and the gateway refused". Callers must NOT vary their response to the client on
 * it: the sign-in endpoint answers identically either way, or it becomes the residency-ID
 * enumeration oracle that beginOtpLogin is written to avoid.
 */
export class OtpThrottledError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OtpThrottledError';
  }
}

const sha256 = (v: string): string => createHash('sha256').update(v).digest('hex');

function hashesEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export type OtpVerifyResult =
  | { ok: true; residentId: string }
  | { ok: false; reason: 'NO_CHALLENGE' | 'EXPIRED' | 'LOCKED' | 'WRONG_CODE' };

export class OtpService {
  constructor(
    private store: OtpStore,
    private sender: OtpSender,
    private newId: () => string,
    private codeLength = 6,
    private limits: OtpLimits = DEFAULT_OTP_LIMITS,
  ) {}

  /** Start of the current rolling window, as an ISO timestamp. */
  private windowStart(): string {
    return new Date(Date.now() - this.limits.windowSeconds * 1000).toISOString();
  }

  /**
   * Issue a code for a resident and hand it to the sender for delivery.
   *
   * Returns the channel the sender used, never the code itself: the code exists only in
   * the delivered message and, hashed, in the store. A caller (the login controller) must
   * not be able to read it, or the fallback factor would be no factor at all.
   */
  async issue(residentId: string): Promise<{ channel: string }> {
    // Refuse before generating or sending anything. An attacker who can call this freely
    // gets both unlimited fresh targets to guess at and an SMS bill charged to the
    // deployment, delivered to a resident who is not trying to sign in.
    const recent = await this.store.recentFor(residentId, this.windowStart());
    if (recent.length >= this.limits.maxChallengesPerWindow) {
      throw new OtpThrottledError(
        `resident has been sent ${recent.length} codes in the last ` +
          `${Math.round(this.limits.windowSeconds / 60)} minutes; no further codes will be ` +
          'issued until the window clears',
      );
    }

    const code = String(randomInt(0, 10 ** this.codeLength)).padStart(this.codeLength, '0');
    const now = new Date();
    const challenge: OtpChallengeRecord = {
      id: this.newId(),
      residentId,
      codeHash: sha256(code),
      channel: 'pending',
      expiresAt: new Date(now.getTime() + this.limits.ttlSeconds * 1000).toISOString(),
      consumed: false,
      failedAttempts: 0,
      createdAt: now.toISOString(),
    };
    await this.store.save(challenge);

    const { channel } = await this.sender.send(residentId, code);
    challenge.channel = channel;
    await this.store.update(challenge);
    return { channel };
  }

  /**
   * Verify a submitted code. Consumes the challenge on success, counts the failure and
   * locks the challenge on too many misses.
   */
  async verify(residentId: string, code: string): Promise<OtpVerifyResult> {
    const challenge = await this.store.findActive(residentId);
    if (!challenge || challenge.consumed) return { ok: false, reason: 'NO_CHALLENGE' };

    if (new Date(challenge.expiresAt).getTime() < Date.now()) {
      return { ok: false, reason: 'EXPIRED' };
    }
    if (challenge.failedAttempts >= this.limits.maxAttemptsPerChallenge) {
      return { ok: false, reason: 'LOCKED' };
    }

    // The bound that matters. Summed across every challenge in the window, so issuing a
    // fresh code does not hand the attacker a fresh allowance -- the counter follows the
    // resident, not the challenge.
    const recent = await this.store.recentFor(residentId, this.windowStart());
    const failuresThisWindow = recent.reduce((n, c) => n + c.failedAttempts, 0);
    if (failuresThisWindow >= this.limits.maxAttemptsPerWindow) {
      return { ok: false, reason: 'LOCKED' };
    }

    if (!hashesEqual(sha256(code), challenge.codeHash)) {
      challenge.failedAttempts += 1;
      await this.store.update(challenge);
      return { ok: false, reason: 'WRONG_CODE' };
    }

    // Single use: consume before returning, so a code cannot be replayed even within its
    // validity window.
    challenge.consumed = true;
    await this.store.update(challenge);
    return { ok: true, residentId };
  }
}
