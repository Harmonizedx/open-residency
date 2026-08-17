// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from 'node:crypto';
import { IssuerKey } from '../credentials/keystore';
import { signJwt } from '../credentials/signer';
import { CONSENT_LEGAL_BASIS_ID, LegalBasis, LegalBasisRegistry } from './legal-basis';

/**
 * Consent framework (ORCS §9).
 *
 * When a citizen lets a sector service (Health, Tax, ...) read residency claims via
 * SSO, that permission is recorded as a first-class ConsentRecord, not just an
 * ephemeral OIDC session grant. The citizen can list and revoke consents, and each
 * grant produces a signed, portable ConsentReceipt (a compact JWT) they can keep as
 * proof of what they agreed to and when. This mirrors data-protection expectations
 * (purpose limitation, revocability, evidence) rather than bolting them on later.
 *
 * §9 requires a grant to capture "subject, controller, processor, purpose, data categories,
 * scope, expiry and evidence of agreement", and every `legalBasisReference` to resolve
 * through the Legal Basis Registry. The record previously held subject, purpose, scope and
 * expiry -- the four that describe what the RELYING PARTY gets -- and none of the four that
 * say who is accountable for it. A citizen could see that Health read their residence claim
 * and could not see which body was the controller, under what authority, or on what evidence
 * they were taken to have agreed. Those are the questions a data-protection regulator asks
 * first, and they were the ones the record could not answer.
 *
 * A grant is REFUSED when it cannot be recorded properly rather than written with blanks, on
 * the same reasoning as a credential revocation: an optional accountability field is one that
 * gets filled with an empty string within a month, and a register full of empty strings is
 * worse than one that made the caller supply an answer.
 */

export type ConsentStatus = 'active' | 'revoked' | 'expired' | 'replaced';

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

/**
 * How the citizen's agreement was captured (ORCS §9, "evidence of agreement").
 *
 * The point of recording it is that "they consented" is a claim the deployment makes about a
 * person, and a claim of that kind has to be traceable to something. `reference` is where the
 * agreement itself is retained -- the interaction session, the signed form, the USSD
 * transaction -- so a disputed grant can be checked against the artefact rather than against
 * the assertion that it happened.
 */
export interface ConsentEvidence {
  method:
    | 'sso_consent_screen'
    | 'operator_recorded'
    | 'signed_form'
    | 'ussd_confirmation'
    | 'imported_record'
    /**
     * Only ever produced by READING a row written before §9 evidence existed. Refused on
     * write: a grant may not claim its evidence is unrecorded, and the value exists so that
     * the absence stays legible instead of being dressed up as some method nobody used.
     */
    | 'unrecorded';
  /** When agreement was given, which is not always when the record was written. */
  at: string;
  /** Where the agreement is retained: a session id, form id, document or transaction ref. */
  reference: string;
  /** The operator who captured it, when a person did rather than the citizen directly. */
  capturedBy?: string;
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
  /** The body accountable for the processing (ORCS §9). */
  controller: string;
  /** The body processing on the controller's behalf, when one does. */
  processor?: string;
  /** Classes of personal data released, distinct from the OIDC scopes carrying them. */
  dataCategories: string[];
  /** Evidence that the citizen agreed. */
  evidence: ConsentEvidence;
  /** Resolves through the Legal Basis Registry (ORCS §9). Never free text. */
  legalBasisReference: string;
  /**
   * Version of this permission, starting at 1.
   *
   * §9 requires replacement to "preserve the previous record and create a new version". A
   * re-grant with different scopes used to leave the old record `'active'` alongside the new
   * one, so a resident had two live consents for the same relying party and no statement of
   * which superseded which. The chain is explicit instead.
   */
  version: number;
  /** The record this one replaced. */
  supersedesId?: string;
  /** The record that replaced this one. Set when status is `'replaced'`. */
  supersededById?: string;
  /** Who withdrew it: the citizen, or an operator acting on their request. */
  withdrawnBy?: string;
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
  /** Classes of personal data released. Required: §9 lists it separately from scope. */
  dataCategories: string[];
  /** How the citizen's agreement was captured. Required. */
  evidence: ConsentEvidence;
  /** Legal basis id. Defaults to the deployment's, which defaults to consent itself. */
  legalBasisReference?: string;
  /** Overrides the deployment controller, for processing another body is accountable for. */
  controller?: string;
  processor?: string;
}

/**
 * The deployment's data-protection posture.
 *
 * The controller is a property of the deployment, not of each grant: one subnational
 * government runs one instance and is the body accountable for what it processes. It is
 * declared once here rather than passed on every call, so a caller cannot name a different
 * controller by accident, and so a deployment that has not decided who its controller is
 * finds out at the first grant instead of shipping a register of blanks.
 */
export interface ConsentPolicy {
  controller: string;
  processor?: string;
  legalBases: LegalBasisRegistry;
  /** Basis for grants that name none. Defaults to consent itself. */
  defaultLegalBasisReference?: string;
}

export type GrantOutcome =
  | { ok: true; record: ConsentRecord; receipt: string }
  | { ok: false; reason: string };

export class ConsentService {
  constructor(
    private store: ConsentStore,
    private key: IssuerKey,
    private issuerDid: string,
    private policy: ConsentPolicy,
  ) {}

  /** The registry every `legalBasisReference` on this deployment resolves through. */
  legalBases(): LegalBasisRegistry {
    return this.policy.legalBases;
  }

  async grant(input: GrantInput): Promise<GrantOutcome> {
    const controller = (input.controller ?? this.policy.controller)?.trim();
    if (!controller) return { ok: false, reason: 'CONTROLLER_REQUIRED' };
    if (!input.dataCategories?.some((c) => c.trim())) {
      return { ok: false, reason: 'DATA_CATEGORIES_REQUIRED' };
    }
    if (
      !input.evidence?.reference?.trim() ||
      !input.evidence?.method ||
      input.evidence.method === 'unrecorded'
    ) {
      return { ok: false, reason: 'EVIDENCE_OF_AGREEMENT_REQUIRED' };
    }
    if (!Number.isFinite(Date.parse(input.evidence.at ?? ''))) {
      return { ok: false, reason: 'EVIDENCE_TIMESTAMP_REQUIRED' };
    }

    // The closed vocabulary, applied. An unregistered or withdrawn basis resolves to nothing
    // and the grant is refused -- recording the reference anyway would leave a consent whose
    // stated authority nobody can look up, which is the free-text string with extra steps.
    const legalBasisReference =
      input.legalBasisReference?.trim() ||
      this.policy.defaultLegalBasisReference?.trim() ||
      CONSENT_LEGAL_BASIS_ID;
    const basis = this.policy.legalBases.resolve(legalBasisReference);
    if (!basis) {
      return {
        ok: false,
        reason: this.policy.legalBases.get(legalBasisReference)
          ? 'LEGAL_BASIS_NOT_IN_FORCE'
          : 'UNKNOWN_LEGAL_BASIS',
      };
    }

    const processor = (input.processor ?? this.policy.processor)?.trim() || undefined;
    const dataCategories = input.dataCategories.map((c) => c.trim()).filter(Boolean);

    // Reuse an existing active consent for the same resident+RP+scopes if present.
    //
    // This must go through the expiry-aware read, not the store directly. Reusing a lapsed
    // grant would resurrect it -- the citizen's 30-day consent silently becoming perpetual
    // at the moment they were asked to consent again.
    const existing = await this.findActive(input.residentId, input.relyingParty);
    if (
      existing &&
      sameScopes(existing.scopes, input.scopes) &&
      sameScopes(existing.dataCategories, dataCategories) &&
      existing.legalBasisReference === legalBasisReference
    ) {
      // Adopt the caller's grant id if this reuse authorized a different grant than the one
      // on record. Letting the record keep a stale id would quietly untrack the live grant,
      // and revoking the consent would then destroy an already-dead grant while the real
      // session carried on -- the exact failure this linkage exists to prevent.
      if (input.grantId && input.grantId !== existing.grantId) {
        const updated = { ...existing, grantId: input.grantId };
        await this.store.update(updated);
        return { ok: true, record: updated, receipt: await this.signReceipt(updated) };
      }
      const receipt = await this.signReceipt(existing);
      return { ok: true, record: existing, receipt };
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
      controller,
      processor,
      dataCategories,
      evidence: { ...input.evidence, reference: input.evidence.reference.trim() },
      legalBasisReference,
      version: existing ? existing.version + 1 : 1,
      supersedesId: existing?.id,
    };
    await this.store.save(record);

    // §9 Replace: preserve the previous record and create a new version. The old permission
    // is closed with a pointer forward rather than left `'active'` beside its successor --
    // two live consents for one relying party is not a history, it is an ambiguity, and the
    // revocation path would only have found one of them.
    if (existing) {
      // `revokedAt` is deliberately NOT set. The citizen did not withdraw anything -- they
      // broadened or narrowed what they share -- and this record is returned verbatim to the
      // citizen-facing listing and to a subject-access export, where a `revokedAt` would read
      // as a withdrawal that never happened. When the supersession occurred is the successor's
      // `grantedAt`, reachable through `supersededById`, so nothing is lost by leaving it unset.
      await this.store.update({
        ...existing,
        status: 'replaced',
        supersededById: record.id,
      });
    }

    const receipt = await this.signReceipt(record);
    return { ok: true, record, receipt };
  }

  /**
   * Withdraw a consent.
   *
   * No reason is required: withdrawal is the citizen's right and demanding they justify it
   * would be a barrier dressed as an audit trail. Who acted IS recorded, because a withdrawal
   * keyed by an operator on someone's behalf and one the citizen made themselves are
   * different events, and a register that cannot tell them apart cannot answer a complaint
   * that a consent was cancelled without the person asking.
   */
  async revoke(id: string, withdrawnBy?: string): Promise<ConsentRecord | null> {
    const record = await this.store.findById(id);
    if (!record || record.status !== 'active') return record ?? null;
    record.status = 'revoked';
    record.revokedAt = new Date().toISOString();
    if (withdrawnBy?.trim()) record.withdrawnBy = withdrawnBy.trim();
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
   * The permission that governs this relying party's reads, whatever its status.
   *
   * Not `findActive`: a lapsed consent is exactly the record `mayProcess` has to see, because
   * whether the lapse stops processing depends on the legal basis it cites. Filtering it out
   * here would decide the question before asking it, and a statutory basis would be silently
   * ignored the moment the consent expired. Replaced records are excluded -- they have been
   * superseded by a live one, and the successor is what governs.
   */
  async governing(residentId: string, relyingParty: string): Promise<ConsentRecord | null> {
    const all = await this.store.listByResident(residentId);
    const candidates = all.filter((r) => r.relyingParty === relyingParty && r.status !== 'replaced');
    if (candidates.length === 0) return null;
    return candidates.reduce((newest, r) =>
      Date.parse(r.grantedAt) > Date.parse(newest.grantedAt) ? r : newest,
    );
  }

  /**
   * May this relying party still be given the claims, and on what authority?
   *
   * ORCS §9 Expire: "Prevent further processing automatically, UNLESS another valid legal
   * basis applies." The exception is the whole reason the legal basis is recorded separately
   * from the consent status. Where a jurisdiction processes under a statutory duty, the
   * citizen withdrawing consent does not repeal the statute -- and equally, where consent IS
   * the basis, its withdrawal must stop processing at once.
   *
   * So the answer turns on the KIND of basis, not on whether one is present: a consent-based
   * grant dies with the consent, a statute-based one survives it for as long as the statute
   * is in force. Treating any resolvable basis as sufficient would let a withdrawn consent
   * keep authorising the read, which is the failure §9 is written to prevent.
   */
  mayProcess(
    record: ConsentRecord,
    now: Date = new Date(),
  ): { permitted: boolean; basis: LegalBasis | null; reason: string } {
    const basis = this.policy.legalBases.resolve(record.legalBasisReference, now);
    if (!basis) return { permitted: false, basis: null, reason: 'LEGAL_BASIS_NOT_IN_FORCE' };

    // Replacement is checked BEFORE the other-basis exception, and withdrawal and expiry are
    // checked after. The exception exists because a citizen's consent lapsing does not repeal a
    // statute -- but a superseded record is not a lapsed permission, it is the wrong version of
    // one. Its scopes have been restated by its successor, so honouring it under a statutory
    // basis would authorise the OLD, often wider, scope set that the citizen has since narrowed.
    if (record.status === 'replaced') return { permitted: false, basis, reason: 'CONSENT_REPLACED' };

    if (basis.kind !== 'consent') {
      return { permitted: true, basis, reason: `OTHER_LEGAL_BASIS_${basis.kind.toUpperCase()}` };
    }
    if (record.status === 'revoked') return { permitted: false, basis, reason: 'CONSENT_WITHDRAWN' };
    if (record.status !== 'active' || isExpired(record, now)) {
      return { permitted: false, basis, reason: 'CONSENT_EXPIRED' };
    }
    return { permitted: true, basis, reason: 'CONSENT_ACTIVE' };
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
        // §9's accountability fields belong on the citizen's copy, not only in the register.
        // The receipt is what they hold when they want to challenge the processing, and a
        // receipt that cannot name the controller or the authority relied on leaves them
        // having to ask the same body they are complaining about.
        controller: record.controller,
        processor: record.processor,
        dataCategories: record.dataCategories,
        legalBasisReference: record.legalBasisReference,
        evidence: record.evidence,
        version: record.version,
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
