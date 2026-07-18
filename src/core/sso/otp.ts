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
 *     if the number of attempts against it is bounded.
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

const OTP_TTL_SECONDS = 5 * 60;
const MAX_OTP_ATTEMPTS = 5;

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
  ) {}

  /**
   * Issue a code for a resident and hand it to the sender for delivery.
   *
   * Returns the channel the sender used, never the code itself: the code exists only in
   * the delivered message and, hashed, in the store. A caller (the login controller) must
   * not be able to read it, or the fallback factor would be no factor at all.
   */
  async issue(residentId: string): Promise<{ channel: string }> {
    const code = String(randomInt(0, 10 ** this.codeLength)).padStart(this.codeLength, '0');
    const now = new Date();
    const challenge: OtpChallengeRecord = {
      id: this.newId(),
      residentId,
      codeHash: sha256(code),
      channel: 'pending',
      expiresAt: new Date(now.getTime() + OTP_TTL_SECONDS * 1000).toISOString(),
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
    if (challenge.failedAttempts >= MAX_OTP_ATTEMPTS) {
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
