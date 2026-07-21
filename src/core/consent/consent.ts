import { createHash } from 'node:crypto';
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
    const existing = await this.store.findActive(input.residentId, input.relyingParty);
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

  listByResident(residentId: string): Promise<ConsentRecord[]> {
    return this.store.listByResident(residentId);
  }

  /** The active consent for a resident+RP pair, if any. */
  findActive(residentId: string, relyingParty: string): Promise<ConsentRecord | null> {
    return this.store.findActive(residentId, relyingParty);
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
  const h = createHash('sha256')
    .update(`${Date.now()}:${Math.random()}:${process.hrtime.bigint()}`)
    .digest('hex')
    .slice(0, 20);
  return `${prefix}_${h}`;
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
