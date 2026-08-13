// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from 'node:crypto';
import { IssuerKey } from '../credentials/keystore';
import { signJwt } from '../credentials/signer';

/**
 * Consent framework.
 *
 * When a citizen lets a sector service (Health, Tax, ...) read residency claims via
 * SSO, that permission is recorded as a first-class ConsentRecord, not just an
 * ephemeral OIDC session grant. The citizen can list and revoke consents, and each
 * grant produces a signed, portable ConsentReceipt (a compact JWT) they can keep as
 * proof of what they agreed to and when. This mirrors data-protection expectations
 * (purpose limitation, revocability, evidence) rather than bolting them on later.
 */

export type ConsentStatus = 'active' | 'revoked' | 'expired';

/**
 * Has this grant's expiry already passed?
 *
 * `expiresAt` was written at grant time and then read nowhere, so a consent created with
 * `validityDays: 30` kept authorizing claim release for ever: `status` stayed `'active'`
 * and every read gated on `status` alone. An expiry that only exists in the record is a
 * promise to the citizen that the system does not keep.
 *
 * The rule lives here, once, and `ConsentService` applies it on every read path. Stores
 * deliberately do NOT duplicate it as a query predicate: a store that filtered expired rows
 * out would hide them from the service, and the service could no longer transition them to
 * `'expired'` -- the record would sit `'active'` in the database for ever while behaving as
 * expired, which is the harder bug to see.
 */
export function isExpired(record: ConsentRecord, now: Date = new Date()): boolean {
  if (!record.expiresAt) return false;
  const at = Date.parse(record.expiresAt);
  return Number.isFinite(at) && at <= now.getTime();
}

export interface ConsentRecord {
  id: string;
  subjectRef: string; // tokenized resident reference (not the raw id)
  residentId: string;
  relyingParty: string; // OIDC client_id, e.g. 'health'
  relyingPartyName?: string;
  purpose: string; // human-readable purpose of processing
  scopes: string[]; // OIDC scopes / claim groups shared
  status: ConsentStatus;
  grantedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  receiptId: string;
  /**
   * The OIDC grant this consent authorized, when it was created through the SSO consent
   * step.
   *
   * Without it the consent record and the grant that actually releases claims are two
   * independent stores with no link, so withdrawing consent leaves the grant live and the
   * citizen keeps being read for the life of the tokens. Recording it is what lets the
   * delivery layer revoke both together. Absent for consents created directly over the
   * consent API, which authorize no session.
   */
  grantId?: string;
}

export interface ConsentStore {
  save(record: ConsentRecord): Promise<ConsentRecord>;
  findById(id: string): Promise<ConsentRecord | null>;
  findActive(residentId: string, relyingParty: string): Promise<ConsentRecord | null>;
  listByResident(residentId: string): Promise<ConsentRecord[]>;
  update(record: ConsentRecord): Promise<ConsentRecord>;
}

export interface GrantInput {
  subjectRef: string;
  residentId: string;
  relyingParty: string;
  relyingPartyName?: string;
  purpose: string;
  scopes: string[];
  validityDays?: number;
  /** OIDC grant this consent authorizes, when created through the SSO consent step. */
  grantId?: string;
}

export class ConsentService {
  constructor(
    private store: ConsentStore,
    private key: IssuerKey,
    private issuerDid: string,
  ) {}

  async grant(input: GrantInput): Promise<{ record: ConsentRecord; receipt: string }> {
    // Reuse an existing active consent for the same resident+RP+scopes if present.
    //
    // This must go through the expiry-aware read, not the store directly. Reusing a lapsed
    // grant would resurrect it -- the citizen's 30-day consent silently becoming perpetual
    // at the moment they were asked to consent again.
    const existing = await this.findActive(input.residentId, input.relyingParty);
    if (existing && sameScopes(existing.scopes, input.scopes)) {
      // Adopt the caller's grant id if this reuse authorized a different grant than the one
      // on record. Letting the record keep a stale id would quietly untrack the live grant,
      // and revoking the consent would then destroy an already-dead grant while the real
      // session carried on -- the exact failure this linkage exists to prevent.
      if (input.grantId && input.grantId !== existing.grantId) {
        const updated = { ...existing, grantId: input.grantId };
        await this.store.update(updated);
        return { record: updated, receipt: await this.signReceipt(updated) };
      }
      const receipt = await this.signReceipt(existing);
      return { record: existing, receipt };
    }

    const now = new Date();
    const record: ConsentRecord = {
      id: randomId('csnt'),
      subjectRef: input.subjectRef,
      residentId: input.residentId,
      relyingParty: input.relyingParty,
      relyingPartyName: input.relyingPartyName,
      purpose: input.purpose,
      scopes: input.scopes,
      status: 'active',
      grantedAt: now.toISOString(),
      expiresAt: input.validityDays
        ? new Date(now.getTime() + input.validityDays * 86400_000).toISOString()
        : undefined,
      receiptId: randomId('rcpt'),
      grantId: input.grantId,
    };
    await this.store.save(record);
    const receipt = await this.signReceipt(record);
    return { record, receipt };
  }

  async revoke(id: string): Promise<ConsentRecord | null> {
    const record = await this.store.findById(id);
    if (!record || record.status !== 'active') return record ?? null;
    record.status = 'revoked';
    record.revokedAt = new Date().toISOString();
    return this.store.update(record);
  }

  /**
   * Every consent for a resident, with lapsed grants reported as `'expired'`.
   *
   * This is what the citizen and an auditor see, so it must not show a grant as live when it
   * is not. Convergence of the stored row is left to `findActive`/`expireDue`: a list read is
   * the wrong place to take a write.
   */
  async listByResident(residentId: string, now: Date = new Date()): Promise<ConsentRecord[]> {
    const records = await this.store.listByResident(residentId);
    return records.map((r) =>
      r.status === 'active' && isExpired(r, now) ? { ...r, status: 'expired' as const } : r,
    );
  }

  /**
   * The active consent for a resident+RP pair, if any.
   *
   * A lapsed grant is not active. It is also transitioned in place, so the stored state
   * converges on first read rather than drifting until a sweep happens to run.
   */
  async findActive(
    residentId: string,
    relyingParty: string,
    now: Date = new Date(),
  ): Promise<ConsentRecord | null> {
    const record = await this.store.findActive(residentId, relyingParty);
    if (!record) return null;
    if (!isExpired(record, now)) return record;
    await this.store.update({ ...record, status: 'expired' });
    return null;
  }

  /**
   * Transition every lapsed grant for a resident to `'expired'`, returning those changed.
   *
   * Read-path enforcement is what makes the guarantee hold; this exists so the register can
   * be brought into line deliberately -- on a subject-access request, or before an export --
   * without waiting for someone to read each grant.
   *
   * Deployment note: there is no scheduled global sweep, because a `CONSENT.EXPIRED` event
   * has nowhere to go until the event registry exists (G-04). Until then, expiry is enforced
   * on read and reconciled per resident here.
   */
  async expireDue(residentId: string, now: Date = new Date()): Promise<ConsentRecord[]> {
    const records = await this.store.listByResident(residentId);
    const changed: ConsentRecord[] = [];
    for (const r of records) {
      if (r.status !== 'active' || !isExpired(r, now)) continue;
      changed.push(await this.store.update({ ...r, status: 'expired' }));
    }
    return changed;
  }

  /**
   * A signed, self-contained consent receipt. Verifiable offline with the issuer
   * public key, so a citizen or a regulator can confirm the grant independently.
   */
  private async signReceipt(record: ConsentRecord): Promise<string> {
    return signJwt(
      this.key.signer,
      { kid: this.key.kid, typ: 'consent-receipt+jwt' },
      {
        receiptId: record.receiptId,
        residentId: record.residentId,
        relyingParty: record.relyingParty,
        purpose: record.purpose,
        scopes: record.scopes,
        status: record.status,
        grantedAt: record.grantedAt,
        // The receipt is the citizen's evidence of what they agreed to. A receipt that
        // cannot say when the permission lapses is part of how the expiry got lost in the
        // first place, so it is stated -- and as `exp`, so any JWT verifier enforces it too.
        expiresAt: record.expiresAt,
        ...(record.expiresAt ? { exp: Math.floor(Date.parse(record.expiresAt) / 1000) } : {}),
        iss: this.issuerDid,
        sub: record.residentId,
      },
    );
  }
}

function sameScopes(a: string[], b: string[]): boolean {
  const sa = [...a].sort().join(' ');
  const sb = [...b].sort().join(' ');
  return sa === sb;
}

function randomId(prefix: string): string {
  // CSPRNG rather than a hash over Date.now()/Math.random(): see the same change in
  // core/audit/audit-log.ts. 10 bytes keeps the identifier the same 20 hex characters
  // it has always been, so stored ids and their format are unaffected.
  return `${prefix}_${randomBytes(10).toString('hex')}`;
}

/** In-memory consent store for tests and pilots. */
export class InMemoryConsentStore implements ConsentStore {
  private byId = new Map<string, ConsentRecord>();
  async save(record: ConsentRecord): Promise<ConsentRecord> {
    this.byId.set(record.id, record);
    return record;
  }
  async findById(id: string): Promise<ConsentRecord | null> {
    return this.byId.get(id) ?? null;
  }
  async findActive(residentId: string, relyingParty: string): Promise<ConsentRecord | null> {
    for (const r of this.byId.values()) {
      if (r.residentId === residentId && r.relyingParty === relyingParty && r.status === 'active') {
        return r;
      }
    }
    return null;
  }
  async listByResident(residentId: string): Promise<ConsentRecord[]> {
    return [...this.byId.values()].filter((r) => r.residentId === residentId);
  }
  async update(record: ConsentRecord): Promise<ConsentRecord> {
    this.byId.set(record.id, record);
    return record;
  }
}
