import { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { generateTotpSecret, totpEnrolmentUri, verifyTotp } from './totp';

/**
 * Operator identity: who, exactly, performed a privileged action.
 *
 * The system previously authenticated privileged routes with one shared static API key.
 * That is enough to keep the registry off the public internet and nothing more: it
 * carries no identity, so every enrolment and every revocation audited to the literal
 * string 'admin', and the audit log could not answer the first question anyone asks of
 * it -- which member of staff did this. It also had no roles (any key holder could do
 * anything), no second factor, and no rotation short of a restart that cut every client
 * over at once.
 *
 * This module is the identity half of the replacement. It is deliberately transport- and
 * framework-agnostic: the guard in src/common decides HOW a request proves it speaks for
 * an operator (an IdP token, a local session, an API key), and this decides WHO that
 * operator is and WHAT they may do.
 */

/**
 * What an operator is allowed to do.
 *
 * Deliberately coarse. Fine-grained permissions look more rigorous but tend to be
 * configured wrong, and the meaningful separation in a residency registry is between the
 * person who enrols residents, the person who can cancel someone's credential, and the
 * person who reads the audit trail to check on both.
 */
export const OPERATOR_ROLES = ['admin', 'registrar', 'revoker', 'auditor', 'support'] as const;
export type OperatorRole = (typeof OPERATOR_ROLES)[number];

export function isOperatorRole(v: string): v is OperatorRole {
  return (OPERATOR_ROLES as readonly string[]).includes(v);
}

/** The authenticated operator a guard attaches to the request. */
export interface Operator {
  /** Stable internal id. For IdP-authenticated operators this is `oidc:<sub>`. */
  id: string;
  /** Human-readable identifier for the audit trail (email or username). */
  displayName: string;
  roles: OperatorRole[];
  /** How this request proved it speaks for the operator. */
  via: 'oidc' | 'local' | 'apiKey' | 'sharedKey';
}

/**
 * `admin` implies every other role, so a deployment does not have to enumerate them on
 * the one account that has to be able to do everything (including bootstrap the others).
 */
export function operatorHasRole(op: Operator, required: OperatorRole): boolean {
  return op.roles.includes('admin') || op.roles.includes(required);
}

/** The audit `actor` string for an operator. Prefixed so it cannot collide with a residentId. */
export function operatorActor(op: Operator): string {
  return `operator:${op.displayName}`;
}

// ---- persistence ports ----------------------------------------------------

export interface OperatorRecord {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
  /** scrypt hash, `scrypt$<saltHex>$<hashHex>`. Null for IdP-only operators. */
  passwordHash: string | null;
  /** Base32 TOTP secret. Null until the operator enrols a second factor. */
  totpSecret: string | null;
  /** Set once the operator has successfully used their TOTP secret at least once. */
  totpConfirmedAt: string | null;
  failedLogins: number;
  lockedUntil: string | null;
  disabledAt: string | null;
  createdAt: string;
}

/**
 * A long-lived credential for machine callers (an enrolment kiosk, an MDA batch job).
 *
 * Stored only as a SHA-256 hash, like every other credential in this codebase: a dump of
 * this table yields nothing that can be presented. `expiresAt` and `rotatedFrom` are what
 * make rotation a real operation rather than an env-var edit and a restart -- two keys can
 * be valid at once, so callers cut over one at a time and the old key is retired on a
 * schedule instead of all at once.
 */
export interface OperatorKeyRecord {
  id: string;
  operatorId: string;
  label: string;
  keyHash: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  rotatedFrom: string | null;
  createdAt: string;
}

export interface OperatorStore {
  findById(id: string): Promise<OperatorRecord | null>;
  findByEmail(email: string): Promise<OperatorRecord | null>;
  list(): Promise<OperatorRecord[]>;
  count(): Promise<number>;
  create(record: OperatorRecord): Promise<void>;
  update(record: OperatorRecord): Promise<void>;
  findKeyByHash(keyHash: string): Promise<OperatorKeyRecord | null>;
  findKeyById(id: string): Promise<OperatorKeyRecord | null>;
  listKeys(operatorId: string): Promise<OperatorKeyRecord[]>;
  createKey(record: OperatorKeyRecord): Promise<void>;
  updateKey(record: OperatorKeyRecord): Promise<void>;
}

// ---- password hashing -----------------------------------------------------

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
) => Promise<Buffer>;

/**
 * scrypt from node:crypto rather than argon2 or bcrypt from npm.
 *
 * Same reasoning as TOTP above: no native build step and no third-party code on the
 * authentication path, which matters for a package a ministry has to review and deploy
 * into a restricted network. scrypt is memory-hard and is what RFC 7914 specifies; the
 * cost parameters below are the Node defaults (N=16384), which is the commonly cited
 * interactive-login setting.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, saltHex, hashHex] = stored.split('$');
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scryptAsync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

const sha256 = (v: string): string => createHash('sha256').update(v).digest('hex');

// ---- service --------------------------------------------------------------

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;

export type LoginResult =
  | { ok: true; operator: Operator }
  | {
      ok: false;
      reason: 'UNKNOWN' | 'DISABLED' | 'LOCKED' | 'BAD_PASSWORD' | 'MFA_REQUIRED' | 'BAD_MFA';
    };

export interface OperatorServiceOptions {
  /** Refuse local logins from accounts with no confirmed second factor. */
  requireMfa: boolean;
  /** Issuer name shown in the authenticator app. */
  issuerName: string;
}

export class OperatorService {
  constructor(
    private store: OperatorStore,
    private opts: OperatorServiceOptions,
    private newId: () => string = randomUUID,
    private now: () => Date = () => new Date(),
  ) {}

  private toOperator(r: OperatorRecord, via: Operator['via']): Operator {
    return {
      id: r.id,
      displayName: r.displayName || r.email,
      roles: r.roles.filter(isOperatorRole),
      via,
    };
  }

  // ---- account management ----

  async createOperator(input: {
    email: string;
    displayName?: string;
    roles: OperatorRole[];
    password?: string;
  }): Promise<{ record: OperatorRecord; totpSecret: string; totpUri: string }> {
    const existing = await this.store.findByEmail(input.email.toLowerCase());
    if (existing) throw new Error(`An operator already exists for ${input.email}`);
    const totpSecret = generateTotpSecret();
    const record: OperatorRecord = {
      id: this.newId(),
      email: input.email.toLowerCase(),
      displayName: input.displayName ?? input.email,
      roles: input.roles,
      passwordHash: input.password ? await hashPassword(input.password) : null,
      totpSecret,
      totpConfirmedAt: null,
      failedLogins: 0,
      lockedUntil: null,
      disabledAt: null,
      createdAt: this.now().toISOString(),
    };
    await this.store.create(record);
    return {
      record,
      totpSecret,
      totpUri: totpEnrolmentUri(totpSecret, record.email, this.opts.issuerName),
    };
  }

  async setDisabled(operatorId: string, disabled: boolean): Promise<boolean> {
    const r = await this.store.findById(operatorId);
    if (!r) return false;
    r.disabledAt = disabled ? this.now().toISOString() : null;
    await this.store.update(r);
    return true;
  }

  async listOperators(): Promise<OperatorRecord[]> {
    return this.store.list();
  }

  async count(): Promise<number> {
    return this.store.count();
  }

  async findById(id: string): Promise<OperatorRecord | null> {
    return this.store.findById(id);
  }

  /**
   * Resolve a session token's subject to a live operator.
   *
   * Reads the record rather than trusting the roles inside the token, so disabling an
   * account or narrowing its roles takes effect on the very next request instead of
   * whenever the session happens to expire.
   */
  async resolveSession(operatorId: string): Promise<Operator | null> {
    const r = await this.store.findById(operatorId);
    if (!r || r.disabledAt) return null;
    return this.toOperator(r, 'local');
  }

  // ---- local login ----

  /**
   * Password + TOTP login.
   *
   * Failures are counted and the account locks for a fixed window, because a password is
   * only as strong as the number of guesses allowed against it. The lockout is per
   * account rather than per IP: an operator console sits behind a handful of office IPs,
   * so per-IP limiting would be trivially shared and useless here.
   */
  async login(email: string, password: string, totp?: string): Promise<LoginResult> {
    const r = await this.store.findByEmail(email.toLowerCase());
    if (!r || !r.passwordHash) return { ok: false, reason: 'UNKNOWN' };
    if (r.disabledAt) return { ok: false, reason: 'DISABLED' };
    if (r.lockedUntil && new Date(r.lockedUntil).getTime() > this.now().getTime()) {
      return { ok: false, reason: 'LOCKED' };
    }

    if (!(await verifyPassword(password, r.passwordHash))) {
      return this.countFailure(r, 'BAD_PASSWORD');
    }

    // A confirmed secret is always enforced once it exists, regardless of requireMfa: an
    // operator who has enrolled a second factor must not be able to skip it by omitting
    // the field. requireMfa additionally governs accounts that have not enrolled one yet.
    const mfaEnforced = !!r.totpConfirmedAt || this.opts.requireMfa;
    if (mfaEnforced) {
      if (!r.totpSecret) return { ok: false, reason: 'MFA_REQUIRED' };
      if (!totp) return { ok: false, reason: 'MFA_REQUIRED' };
      if (!verifyTotp(r.totpSecret, totp)) return this.countFailure(r, 'BAD_MFA');
      if (!r.totpConfirmedAt) r.totpConfirmedAt = this.now().toISOString();
    }

    r.failedLogins = 0;
    r.lockedUntil = null;
    await this.store.update(r);
    return { ok: true, operator: this.toOperator(r, 'local') };
  }

  private async countFailure(
    r: OperatorRecord,
    reason: 'BAD_PASSWORD' | 'BAD_MFA',
  ): Promise<LoginResult> {
    r.failedLogins += 1;
    if (r.failedLogins >= MAX_FAILED_LOGINS) {
      r.lockedUntil = new Date(this.now().getTime() + LOCKOUT_MINUTES * 60_000).toISOString();
      r.failedLogins = 0;
    }
    await this.store.update(r);
    return { ok: false, reason };
  }

  // ---- API keys ----

  /**
   * Mint an API key for an operator. The plaintext is returned exactly once, here, and
   * only its hash is stored -- so a lost key is replaced, never recovered.
   */
  async issueKey(input: {
    operatorId: string;
    label: string;
    expiresInDays?: number;
    rotatedFrom?: string;
  }): Promise<{ key: string; record: OperatorKeyRecord } | null> {
    const op = await this.store.findById(input.operatorId);
    if (!op || op.disabledAt) return null;
    const key = `ork_${randomBytes(24).toString('hex')}`;
    const record: OperatorKeyRecord = {
      id: this.newId(),
      operatorId: input.operatorId,
      label: input.label,
      keyHash: sha256(key),
      expiresAt: input.expiresInDays
        ? new Date(this.now().getTime() + input.expiresInDays * 86_400_000).toISOString()
        : null,
      lastUsedAt: null,
      revokedAt: null,
      rotatedFrom: input.rotatedFrom ?? null,
      createdAt: this.now().toISOString(),
    };
    await this.store.createKey(record);
    return { key, record };
  }

  /**
   * Rotate a key: mint a replacement and put the old one on a short expiry rather than
   * killing it immediately. The overlap is the entire point -- it is what lets callers
   * move across one at a time instead of every client cutting over on one restart, which
   * is exactly what the shared static key could not do.
   */
  async rotateKey(
    keyId: string,
    overlapHours = 24,
  ): Promise<{ key: string; record: OperatorKeyRecord; retiresAt: string } | null> {
    const old = await this.store.findKeyById(keyId);
    if (!old || old.revokedAt) return null;
    const issued = await this.issueKey({
      operatorId: old.operatorId,
      label: old.label,
      rotatedFrom: old.id,
    });
    if (!issued) return null;
    const retiresAt = new Date(this.now().getTime() + overlapHours * 3_600_000).toISOString();
    // Only shorten: a rotation must never extend a key that already expires sooner.
    if (!old.expiresAt || new Date(old.expiresAt).getTime() > new Date(retiresAt).getTime()) {
      old.expiresAt = retiresAt;
      await this.store.updateKey(old);
    }
    return { ...issued, retiresAt: old.expiresAt! };
  }

  async revokeKey(keyId: string): Promise<boolean> {
    const k = await this.store.findKeyById(keyId);
    if (!k || k.revokedAt) return false;
    k.revokedAt = this.now().toISOString();
    await this.store.updateKey(k);
    return true;
  }

  async listKeys(operatorId: string): Promise<OperatorKeyRecord[]> {
    return this.store.listKeys(operatorId);
  }

  /** Resolve a presented API key to an operator, honouring expiry, revocation and disablement. */
  async authenticateKey(presented: string): Promise<Operator | null> {
    const k = await this.store.findKeyByHash(sha256(presented));
    if (!k || k.revokedAt) return null;
    if (k.expiresAt && new Date(k.expiresAt).getTime() < this.now().getTime()) return null;
    const op = await this.store.findById(k.operatorId);
    if (!op || op.disabledAt) return null;
    k.lastUsedAt = this.now().toISOString();
    await this.store.updateKey(k);
    return this.toOperator(op, 'apiKey');
  }

  /**
   * Resolve an IdP-authenticated operator.
   *
   * The IdP owns the identity and the roles; we do not require a local record for them,
   * because forcing every operator to be provisioned twice is how directory and
   * application state drift apart. A local record, if one exists for the same email, is
   * allowed to ADD roles but its `disabledAt` is honoured -- so a local disable is a kill
   * switch that works even when the IdP is slow to deprovision.
   */
  async resolveFederated(input: {
    subject: string;
    email?: string;
    displayName?: string;
    roles: OperatorRole[];
  }): Promise<Operator | null> {
    const local = input.email ? await this.store.findByEmail(input.email.toLowerCase()) : null;
    if (local?.disabledAt) return null;
    const roles = new Set<OperatorRole>(input.roles);
    for (const r of local?.roles ?? []) if (isOperatorRole(r)) roles.add(r);
    if (roles.size === 0) return null;
    return {
      id: local?.id ?? `oidc:${input.subject}`,
      displayName: input.displayName ?? input.email ?? input.subject,
      roles: [...roles],
      via: 'oidc',
    };
  }
}
