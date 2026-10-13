// SPDX-License-Identifier: Apache-2.0
import { createHash, randomUUID } from 'node:crypto';
import { CryptoKey, decodeJwt, decodeProtectedHeader, errors, importJWK, jwtVerify } from 'jose';
import { Signer, signJwt } from '../credentials/signer';
import { TrustedIssuer, VcVerifier } from '../credentials/vc-verifier';
import {
  DEFAULT_EXCLUSIVITY,
  ExclusivityPolicy,
  ExclusivityRule,
  FederatedIssuer,
} from '../credentials/federation';
import { ResidencyStore } from './ports';
import { ResidencyService } from './residency-service';
import { RelationshipStatus, relationshipOf } from './lifecycle';

/**
 * Arrival notices: how one jurisdiction learns that a person it registered has registered
 * somewhere else, without either register writing to the other.
 *
 * The pattern is the one Germany's registration law uses between municipalities (BMG §33):
 * the authority that registers a mover notifies the one the mover came from, and that notice
 * -- not a shared database -- is what drives deregistration at the old address. Here the
 * mover presents their residency credential at the new jurisdiction's desk; that deployment
 * verifies it through the federation trust list, registers the person, and sends the
 * ISSUING deployment a signed notice. The notice carries the credential's identifier and a
 * hash of the credential as presented, and nothing about the person: no name, no number, no
 * address. The issuing deployment already holds every personal fact the notice could name,
 * so naming them would add disclosure and no information.
 *
 * What the receiving deployment does with a notice is ITS declared rule, per peer:
 *
 *   none    -- note the notice; the two residencies coexist and no conflict exists.
 *   record  -- open a conflict for a person to look at; the relationship is untouched.
 *   suspend -- suspend the relationship once the grace period has run.
 *   end     -- end the relationship once the grace period has run.
 *
 * The rule is the deployment's, the notice is the peer's evidence, and the decision is taken
 * locally: no jurisdiction writes to another's register (ADR-0004), and there is no central
 * adjudicator (ADR-0018). A grace period exists so that a person who disputes the move, or a
 * registrar who recognises an error, can reverse the conflict before anything is applied.
 *
 * Both directions are stored, as evidence: what this deployment sent, and what it received
 * and did about it.
 */

/** The `typ` header of a notice JWT. A credential presented in its place is refused. */
export const ARRIVAL_NOTICE_TYP = 'arrival-notice+jwt';

/** How long a notice stays presentable. A peer unreachable for longer than this gets a fresh one. */
export const ARRIVAL_NOTICE_VALIDITY_DAYS = 30;

/** Signature algorithms a notice may carry; the set the trust list can express keys for. */
const NOTICE_ALGORITHMS = ['EdDSA', 'RS256'] as const;

/**
 * The only claims a notice may carry. Any other claim refuses the notice outright: a peer
 * that starts adding a name or a number to its notices is sending personal data to a
 * register that did not ask for it, and the refusal is what stops that quietly becoming the
 * norm.
 */
const NOTICE_CLAIMS = new Set([
  'iss',
  'aud',
  'jti',
  'iat',
  'exp',
  'nbf',
  'credentialId',
  'presentationHash',
  'presentedAt',
  'registeredAt',
]);

/** Retried this many times by the sweep before an outbound notice is left as failed. */
export const ARRIVAL_NOTICE_MAX_ATTEMPTS = 10;

export type ArrivalNoticeDirection = 'inbound' | 'outbound';

/**
 * Inbound: `noted` (rule none, or nothing to do), `unmatched` (no record here carries that
 * credential), `open` (a conflict for a person), `pending` (a transition falls due at
 * `effectiveAt`), `applied` (the transition was made), `resolved` (a person decided).
 * Outbound: `sent` or `failed`.
 */
export type ArrivalNoticeStatus =
  | 'noted'
  | 'unmatched'
  | 'open'
  | 'pending'
  | 'applied'
  | 'resolved'
  | 'sent'
  | 'failed';

export const ARRIVAL_NOTICE_STATUSES: readonly ArrivalNoticeStatus[] = [
  'noted',
  'unmatched',
  'open',
  'pending',
  'applied',
  'resolved',
  'sent',
  'failed',
];

export type ArrivalNoticeResolution = 'upheld' | 'reversed';

export const ARRIVAL_NOTICE_RESOLUTIONS: readonly ArrivalNoticeResolution[] = ['upheld', 'reversed'];

export interface ArrivalNotice {
  /** The notice's `jti`. Unique across peers; a repeat is a replay and is refused. */
  id: string;
  direction: ArrivalNoticeDirection;
  /** The other jurisdiction: sender of an inbound notice, recipient of an outbound one. */
  peerDid: string;
  peerName?: string;
  /** The credential the person presented: its `jti`. Issued by us (inbound) or by the peer (outbound). */
  credentialId: string;
  /** base64url SHA-256 of the credential exactly as presented. */
  presentationHash: string;
  presentedAt: string;
  registeredAt: string;
  /** When this deployment received (inbound) or first sent (outbound) the notice. */
  at: string;
  /** Inbound: our record for that credential, when one exists. */
  residentId?: string;
  countryCode?: string;
  /** Inbound: the rule this deployment declared for the sending peer, as applied. */
  rule?: ExclusivityRule;
  graceDays?: number;
  /** Inbound, rule suspend|end: when the transition falls due. */
  effectiveAt?: string;
  status: ArrivalNoticeStatus;
  /** Whether this notice opened a conflict under the rule. False under `none`, and when unmatched. */
  conflict: boolean;
  appliedAt?: string;
  appliedTransition?: Extract<RelationshipStatus, 'SUSPENDED' | 'ENDED'>;
  /** Why the rule could not be applied, when the lifecycle refused it. A person looks. */
  applyFailure?: string;
  resolvedAt?: string;
  resolvedBy?: string;
  resolution?: ArrivalNoticeResolution;
  resolutionReason?: string;
  /** Outbound: delivery attempts so far. */
  attempts?: number;
  lastAttemptAt?: string;
  deliveryDetail?: string;
  /** The notice itself, as sent or received. Evidence; verifiable by anyone holding the peer's key. */
  notice: string;
}

export interface ArrivalNoticeStore {
  /** Insert, or replace the row with the same id. */
  save(notice: ArrivalNotice): Promise<void>;
  findById(id: string): Promise<ArrivalNotice | null>;
  list(opts?: {
    direction?: ArrivalNoticeDirection;
    status?: ArrivalNoticeStatus;
    residentId?: string;
    countryCode?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; items: ArrivalNotice[] }>;
  /** Inbound notices whose grace period has run: `pending` with `effectiveAt` at or before `now`. */
  due(now: string): Promise<ArrivalNotice[]>;
  /** Outbound notices whose last delivery failed. */
  failedOutbound(): Promise<ArrivalNotice[]>;
}

export class InMemoryArrivalNoticeStore implements ArrivalNoticeStore {
  private rows = new Map<string, ArrivalNotice>();

  async save(notice: ArrivalNotice): Promise<void> {
    this.rows.set(notice.id, { ...notice });
  }

  async findById(id: string): Promise<ArrivalNotice | null> {
    const n = this.rows.get(id);
    return n ? { ...n } : null;
  }

  async list(opts: Parameters<ArrivalNoticeStore['list']>[0] = {}): Promise<{ total: number; items: ArrivalNotice[] }> {
    const all = [...this.rows.values()]
      .filter((n) => !opts.direction || n.direction === opts.direction)
      .filter((n) => !opts.status || n.status === opts.status)
      .filter((n) => !opts.residentId || n.residentId === opts.residentId)
      .filter((n) => !opts.countryCode || n.countryCode === opts.countryCode)
      .sort((a, b) => a.at.localeCompare(b.at));
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { total: all.length, items: all.slice(offset, offset + limit).map((n) => ({ ...n })) };
  }

  async due(now: string): Promise<ArrivalNotice[]> {
    return [...this.rows.values()]
      .filter((n) => n.direction === 'inbound' && n.status === 'pending' && !!n.effectiveAt && n.effectiveAt <= now)
      .map((n) => ({ ...n }));
  }

  async failedOutbound(): Promise<ArrivalNotice[]> {
    return [...this.rows.values()]
      .filter((n) => n.direction === 'outbound' && n.status === 'failed')
      .map((n) => ({ ...n }));
  }
}

/** base64url SHA-256 of the credential as presented, which is what the notice names. */
export function presentationHashOf(credential: string): string {
  return createHash('sha256').update(credential, 'utf8').digest('base64url');
}

export interface ArrivalNoticeDeps {
  store: ArrivalNoticeStore;
  residents: ResidencyStore;
  residency: ResidencyService;
  /** Verifies the credential a mover presents, before this deployment notifies its issuer. */
  verifier: VcVerifier;
  /** Peer keys, for the signature on an inbound notice. The same map the verifier uses. */
  trust: Map<string, TrustedIssuer>;
  /** The federation trust list: who may send notices here, and under which rule. */
  peers: () => FederatedIssuer[];
  /** The issuer DIDs this deployment signs as, one per jurisdiction config. */
  ownIssuers: () => { countryCode: string; did: string }[];
  signer: Signer;
  /** Transport to a peer's arrival-notice endpoint. Injected so the suite runs without a network. */
  deliver: (url: string, body: { notice: string }) => Promise<void>;
  now?: () => Date;
}

export type NotifyOutcome = { ok: true; notice: ArrivalNotice } | { ok: false; reason: string };

export type ReceiveOutcome =
  | { ok: true; notice: ArrivalNotice }
  | { ok: false; reason: string; kind: 'malformed' | 'untrusted' | 'replay' };

export type ResolveOutcome = { ok: true; notice: ArrivalNotice } | { ok: false; reason: string };

export class ArrivalNoticeService {
  private keyCache = new Map<string, CryptoKey>();

  constructor(private deps: ArrivalNoticeDeps) {}

  private now(): Date {
    return this.deps.now?.() ?? new Date();
  }

  /**
   * The mover presented a peer's credential at this deployment's desk and was registered
   * here. Tell the peer: sign a notice naming the credential, and deliver it to the endpoint
   * the peer published in the trust list.
   *
   * The credential is verified first, through the same trust map as any other verification,
   * so this deployment never notifies a peer about a credential it would not itself accept.
   * A credential this deployment issued is not a move and gets no notice.
   */
  async notify(input: {
    /** The jurisdiction here that registered the mover; names the issuer DID the notice is signed as. */
    countryCode: string;
    /** The credential as presented, in compact VC-JWT form. */
    credential: string;
    presentedAt?: string;
    registeredAt?: string;
  }): Promise<NotifyOutcome> {
    const own = this.deps.ownIssuers().find((o) => o.countryCode.toUpperCase() === input.countryCode.toUpperCase());
    if (!own) return { ok: false, reason: 'UNKNOWN_COUNTRY' };

    const outcome = await this.deps.verifier.verify(input.credential, { offline: true });
    if (!outcome.valid || !outcome.issuerDid) {
      return { ok: false, reason: `CREDENTIAL_${outcome.reason ?? 'INVALID'}` };
    }
    if (this.deps.ownIssuers().some((o) => o.did === outcome.issuerDid)) {
      return { ok: false, reason: 'CREDENTIAL_IS_OURS' };
    }
    const peer = this.deps.peers().find((p) => p.did === outcome.issuerDid);
    if (!peer) return { ok: false, reason: 'UNTRUSTED_ISSUER' };
    if (!peer.arrivalNoticeUrl) return { ok: false, reason: 'PEER_HAS_NO_ARRIVAL_NOTICE_ENDPOINT' };

    let credentialId: string | undefined;
    try {
      const payload = decodeJwt(input.credential);
      const vc = (payload.vc ?? {}) as { id?: unknown };
      credentialId = typeof payload.jti === 'string' ? payload.jti : typeof vc.id === 'string' ? vc.id : undefined;
    } catch {
      credentialId = undefined;
    }
    if (!credentialId) return { ok: false, reason: 'CREDENTIAL_HAS_NO_ID' };

    const now = this.now();
    const at = now.toISOString();
    const id = `urn:uuid:${randomUUID()}`;
    const presentedAt = input.presentedAt ?? at;
    const registeredAt = input.registeredAt ?? at;
    const jwt = await signJwt(
      this.deps.signer,
      { kid: `${own.did}#${this.deps.signer.kid}`, typ: ARRIVAL_NOTICE_TYP },
      {
        iss: own.did,
        aud: peer.did,
        jti: id,
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(now.getTime() / 1000) + ARRIVAL_NOTICE_VALIDITY_DAYS * 86400,
        credentialId,
        presentationHash: presentationHashOf(input.credential),
        presentedAt,
        registeredAt,
      },
    );

    const notice: ArrivalNotice = {
      id,
      direction: 'outbound',
      peerDid: peer.did,
      peerName: peer.name,
      credentialId,
      presentationHash: presentationHashOf(input.credential),
      presentedAt,
      registeredAt,
      at,
      countryCode: own.countryCode,
      status: 'failed',
      conflict: false,
      attempts: 0,
      notice: jwt,
    };
    await this.attemptDelivery(notice, peer.arrivalNoticeUrl);
    await this.deps.store.save(notice);
    return { ok: true, notice };
  }

  private async attemptDelivery(notice: ArrivalNotice, url: string): Promise<void> {
    notice.attempts = (notice.attempts ?? 0) + 1;
    notice.lastAttemptAt = this.now().toISOString();
    try {
      await this.deps.deliver(url, { notice: notice.notice });
      notice.status = 'sent';
      delete notice.deliveryDetail;
    } catch (e) {
      notice.status = 'failed';
      notice.deliveryDetail = String((e as Error)?.message ?? e).slice(0, 512);
    }
  }

  /**
   * A peer says a person holding one of our credentials has registered with it.
   *
   * The notice is accepted only from a peer in the trust list, signed by a key the list
   * holds for it, addressed to one of this deployment's issuer DIDs, within its validity,
   * never seen before, and carrying nothing beyond the claims a notice is allowed. Then the
   * rule this deployment declared for that peer decides what happens, and the notice and the
   * decision are stored together.
   */
  async receive(jwt: string): Promise<ReceiveOutcome> {
    let did: string;
    let keyId: string | undefined;
    let alg: string;
    try {
      const header = decodeProtectedHeader(jwt);
      if (header.typ !== ARRIVAL_NOTICE_TYP) return { ok: false, reason: 'WRONG_TYPE', kind: 'malformed' };
      const kid = String(header.kid ?? '');
      did = kid.split('#')[0];
      keyId = kid.split('#')[1] || undefined;
      alg = String(header.alg ?? '');
    } catch {
      return { ok: false, reason: 'MALFORMED_NOTICE', kind: 'malformed' };
    }
    if (!(NOTICE_ALGORITHMS as readonly string[]).includes(alg)) {
      return { ok: false, reason: 'UNSUPPORTED_ALGORITHM', kind: 'malformed' };
    }

    const peer = this.deps.peers().find((p) => p.did === did);
    const keys = peer ? await this.keysFor(did, keyId, alg) : [];
    if (!peer || keys.length === 0) return { ok: false, reason: 'UNTRUSTED_PEER', kind: 'untrusted' };

    const audience = this.deps.ownIssuers().map((o) => o.did);
    let payload: Record<string, unknown> | undefined;
    let failure = 'BAD_SIGNATURE';
    for (const key of keys) {
      try {
        const res = await jwtVerify(jwt, key, { issuer: did, audience, typ: ARRIVAL_NOTICE_TYP, algorithms: [alg] });
        payload = res.payload as Record<string, unknown>;
        break;
      } catch (e) {
        if (e instanceof errors.JWTExpired) {
          failure = 'EXPIRED';
          break;
        }
        if (e instanceof errors.JWTClaimValidationFailed) {
          failure = e.claim === 'aud' ? 'NOT_ADDRESSED_TO_THIS_DEPLOYMENT' : `CLAIM_${e.claim.toUpperCase()}_REJECTED`;
          break;
        }
      }
    }
    if (!payload) return { ok: false, reason: failure, kind: 'untrusted' };

    for (const claim of Object.keys(payload)) {
      if (!NOTICE_CLAIMS.has(claim)) return { ok: false, reason: `UNEXPECTED_CLAIM_${claim}`, kind: 'malformed' };
    }
    const jti = payload.jti;
    const credentialId = payload.credentialId;
    const presentationHash = payload.presentationHash;
    const presentedAt = payload.presentedAt;
    const registeredAt = payload.registeredAt;
    if (
      typeof jti !== 'string' ||
      !jti ||
      typeof credentialId !== 'string' ||
      !credentialId ||
      typeof presentationHash !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(presentationHash) ||
      typeof presentedAt !== 'string' ||
      Number.isNaN(Date.parse(presentedAt)) ||
      typeof registeredAt !== 'string' ||
      Number.isNaN(Date.parse(registeredAt))
    ) {
      return { ok: false, reason: 'MISSING_OR_MALFORMED_CLAIMS', kind: 'malformed' };
    }

    if (await this.deps.store.findById(jti)) return { ok: false, reason: 'REPLAY', kind: 'replay' };

    const at = this.now().toISOString();
    const notice: ArrivalNotice = {
      id: jti,
      direction: 'inbound',
      peerDid: did,
      peerName: peer.name,
      credentialId,
      presentationHash,
      presentedAt,
      registeredAt,
      at,
      status: 'noted',
      conflict: false,
      notice: jwt,
    };

    const record = await this.deps.residents.findByCredentialId(credentialId);
    if (!record) {
      notice.status = 'unmatched';
      await this.deps.store.save(notice);
      return { ok: true, notice };
    }
    notice.residentId = record.residentId;
    notice.countryCode = record.countryCode;

    const policy: ExclusivityPolicy = peer.exclusivity ?? DEFAULT_EXCLUSIVITY;
    notice.rule = policy.rule;
    notice.graceDays = policy.graceDays;

    const relationship = relationshipOf(record);
    if (policy.rule === 'none') {
      notice.status = 'noted';
    } else if (relationship.status === 'ENDED' || relationship.status === 'REVOKED' || relationship.status === 'EXPIRED') {
      // Nothing holds here any more; there is no second claim for a rule to act on.
      notice.status = 'noted';
      notice.applyFailure = `RELATIONSHIP_ALREADY_${relationship.status}`;
    } else if (policy.rule === 'record') {
      notice.status = 'open';
      notice.conflict = true;
    } else {
      notice.conflict = true;
      notice.effectiveAt = new Date(Date.parse(at) + policy.graceDays * 86_400_000).toISOString();
      if (policy.graceDays === 0) await this.apply(notice);
      else notice.status = 'pending';
    }
    await this.deps.store.save(notice);
    return { ok: true, notice };
  }

  /** Apply the rule's transition to the relationship, attributing it to the rule and the peer. */
  private async apply(notice: ArrivalNotice): Promise<boolean> {
    const to = notice.rule === 'end' ? 'ENDED' : 'SUSPENDED';
    const result = await this.deps.residency.transitionRelationship(notice.residentId!, {
      to,
      by: `rule:exclusivity:${notice.peerDid}`,
      reason:
        `Arrival notice ${notice.id}: registered with ${notice.peerName ?? notice.peerDid} ` +
        `on ${notice.registeredAt}; this deployment's rule for that peer is "${notice.rule}"`,
      at: this.now().toISOString(),
    });
    if (result.ok) {
      notice.status = 'applied';
      notice.appliedAt = this.now().toISOString();
      notice.appliedTransition = to;
      delete notice.applyFailure;
      return true;
    }
    notice.status = 'open';
    notice.applyFailure = result.reason;
    return false;
  }

  /**
   * Apply every inbound notice whose grace period has run. Returns what was applied, so the
   * caller can audit each one; a refusal leaves the notice `open` for a person.
   */
  async applyDue(now: Date = this.now()): Promise<ArrivalNotice[]> {
    const applied: ArrivalNotice[] = [];
    for (const notice of await this.deps.store.due(now.toISOString())) {
      await this.apply(notice);
      await this.deps.store.save(notice);
      applied.push(notice);
    }
    return applied;
  }

  /** Re-send outbound notices whose delivery failed, up to the attempt limit. */
  async retryFailed(): Promise<{ sent: ArrivalNotice[]; failed: ArrivalNotice[] }> {
    const sent: ArrivalNotice[] = [];
    const failed: ArrivalNotice[] = [];
    for (const notice of await this.deps.store.failedOutbound()) {
      if ((notice.attempts ?? 0) >= ARRIVAL_NOTICE_MAX_ATTEMPTS) continue;
      const peer = this.deps.peers().find((p) => p.did === notice.peerDid);
      if (!peer?.arrivalNoticeUrl) continue;
      await this.attemptDelivery(notice, peer.arrivalNoticeUrl);
      await this.deps.store.save(notice);
      (notice.status === 'sent' ? sent : failed).push(notice);
    }
    return { sent, failed };
  }

  /**
   * A person decides. `upheld` on a pending notice applies the rule now; `reversed` on a
   * pending notice cancels it; `reversed` on a suspension reinstates the relationship. An
   * ended relationship cannot be reversed from here -- ENDED is terminal (ADR-0007) and the
   * person re-enrols -- which is the reason the grace period exists.
   */
  async resolve(
    id: string,
    req: { by: string; resolution: ArrivalNoticeResolution; reason: string },
  ): Promise<ResolveOutcome> {
    const notice = await this.deps.store.findById(id);
    if (!notice) return { ok: false, reason: 'UNKNOWN_NOTICE' };
    if (notice.direction !== 'inbound') return { ok: false, reason: 'OUTBOUND_NOTICE_NOT_RESOLVABLE' };
    if (!req.by?.trim()) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    if (notice.status === 'resolved') return { ok: false, reason: 'ALREADY_RESOLVED' };
    if (notice.status === 'noted' || notice.status === 'unmatched') return { ok: false, reason: 'NOTHING_TO_RESOLVE' };

    if (notice.status === 'pending') {
      if (req.resolution === 'upheld') {
        const applied = await this.apply(notice);
        if (!applied) {
          await this.deps.store.save(notice);
          return { ok: false, reason: notice.applyFailure ?? 'APPLY_REFUSED' };
        }
      }
    } else if (notice.status === 'applied' && req.resolution === 'reversed') {
      if (notice.appliedTransition === 'ENDED') return { ok: false, reason: 'CANNOT_REVERSE_ENDED' };
      const result = await this.deps.residency.transitionRelationship(notice.residentId!, {
        to: 'ACTIVE',
        by: req.by,
        reason: `Arrival notice ${notice.id} reversed: ${req.reason.trim()}`,
        at: this.now().toISOString(),
      });
      if (!result.ok) return { ok: false, reason: result.reason };
    }

    notice.status = 'resolved';
    notice.resolvedAt = this.now().toISOString();
    notice.resolvedBy = req.by.trim();
    notice.resolution = req.resolution;
    notice.resolutionReason = req.reason.trim();
    await this.deps.store.save(notice);
    return { ok: true, notice };
  }

  async get(id: string): Promise<ArrivalNotice | null> {
    return this.deps.store.findById(id);
  }

  async list(opts?: Parameters<ArrivalNoticeStore['list']>[0]): Promise<{ total: number; items: ArrivalNotice[] }> {
    return this.deps.store.list(opts);
  }

  private async keysFor(did: string, kid: string | undefined, alg: string): Promise<CryptoKey[]> {
    const issuer = this.deps.trust.get(did);
    if (!issuer) return [];
    const named = kid ? issuer.publicJwks.filter((j) => j.kid === kid) : [];
    const candidates = named.length ? named : issuer.publicJwks;
    const keys: CryptoKey[] = [];
    for (const jwk of candidates) {
      try {
        const cacheKey = `${did}#${jwk.kid ?? ''}#${alg}#${JSON.stringify(jwk)}`;
        let key = this.keyCache.get(cacheKey);
        if (!key) {
          key = (await importJWK(jwk, alg)) as CryptoKey;
          this.keyCache.set(cacheKey, key);
        }
        keys.push(key);
      } catch {
        continue;
      }
    }
    return keys;
  }
}
