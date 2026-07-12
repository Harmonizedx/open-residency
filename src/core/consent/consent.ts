import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import { IssuerKey } from '../credentials/keystore';

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

  /**
   * A signed, self-contained consent receipt. Verifiable offline with the issuer
   * public key, so a citizen or a regulator can confirm the grant independently.
   */
  private async signReceipt(record: ConsentRecord): Promise<string> {
    return new SignJWT({
      receiptId: record.receiptId,
      residentId: record.residentId,
      relyingParty: record.relyingParty,
      purpose: record.purpose,
      scopes: record.scopes,
      status: record.status,
      grantedAt: record.grantedAt,
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.key.kid, typ: 'consent-receipt+jwt' })
      .setIssuer(this.issuerDid)
      .setSubject(record.residentId)
      .setIssuedAt()
      .sign(this.key.privateKey);
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
