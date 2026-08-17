// SPDX-License-Identifier: Apache-2.0
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { StatusList } from '../core/credentials/status-list';
import { ResidencyStore, ResidentRecord } from '../core/residency/ports';
import {
  LegalBasis,
  LegalBasisDeactivation,
  LegalBasisStore,
} from '../core/consent/legal-basis';
import { RelationshipStatus, RelationshipType } from '../core/residency/lifecycle';
import {
  CredentialStatus,
  StatusPurpose,
} from '../core/credentials/credential-lifecycle';
import { BindingMethod } from '../core/proofing/binding';
import { ResidenceAssuranceLevel, ResidenceEvidenceMethod } from '../core/proofing/residence';
import {
  PendingUpstreamAuth,
  PendingUpstreamAuthStore,
} from '../core/sso/upstream-oidc';
import { AuditEvent, AuditStore } from '../core/audit/audit-log';
import { ConsentRecord, ConsentStore } from '../core/consent/consent';
import { CredentialOfferRecord, NonceRecord, Oid4vciStore } from '../core/oid4vci/ports';
import { Oid4vpStore, PresentationRequestRecord } from '../core/oid4vp/ports';
import { OtpChallengeRecord, OtpStore } from '../core/sso/otp';
import { OidcStore, OidcStoredItem } from '../core/sso/oidc-store';
import { RefusalRecord, RefusalStore, ReviewStatus } from '../core/residency/refusal';
import {
  WebAuthnChallengeRecord,
  WebAuthnChallengeStore,
  WebAuthnCredentialStore,
  StoredCredential,
} from '../core/sso/webauthn-service';
import { WebAuthnAlg } from '../core/sso/webauthn';
import { JWK } from 'jose';
import { OperatorKeyRecord, OperatorRecord, OperatorStore } from '../core/operator/operator';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    // Prisma 7 takes the connection through a driver adapter rather than reading the
    // datasource url out of the schema. DATABASE_URL is unchanged for deployments; what
    // changed is that the client is handed it explicitly here.
    //
    // Checked rather than asserted: an unset DATABASE_URL used to surface as a Prisma
    // validation error naming the variable, and a bare non-null assertion would instead
    // fail somewhere inside pg with a message that does not say which variable is missing.
    const url = process.env.DATABASE_URL;
    if (!url) {
      throw new Error(
        'DATABASE_URL is not set. The residency register needs a PostgreSQL connection ' +
          'string, e.g. postgresql://user:password@host:5432/openres?schema=public',
      );
    }
    super({ adapter: new PrismaPg(url) });
  }

  async onModuleInit() {
    await this.$connect();
  }
  async onModuleDestroy() {
    await this.$disconnect();
  }
}

/**
 * Prisma-backed ResidencyStore. Implements the same port the in-memory store does,
 * so the framework-agnostic ResidencyService runs unchanged against PostgreSQL.
 */
@Injectable()
export class PrismaResidencyStore implements ResidencyStore {
  constructor(private prisma: PrismaService) {}

  private toRecord(r: any): ResidentRecord {
    return {
      id: r.id,
      residentId: r.residentId,
      subjectRef: r.subjectRef,
      countryCode: r.countryCode,
      subnationalUnit: r.subnationalUnit,
      providerCode: r.providerCode,
      assuranceLevel: r.assuranceLevel,
      binding: {
        method: (r.bindingMethod ?? 'none') as BindingMethod,
        ref: r.bindingRef ?? undefined,
        verifiedAt: r.bindingAt ? r.bindingAt.toISOString() : undefined,
        score: r.bindingScore ?? undefined,
      },
      residence: {
        assuranceLevel: (r.residenceAssurance ?? 'RAL0') as ResidenceAssuranceLevel,
        method: (r.residenceMethod ?? 'self_declared') as ResidenceEvidenceMethod,
        unit: r.residenceUnit ?? undefined,
        asOf: r.residenceAsOf ? r.residenceAsOf.toISOString() : undefined,
      },
      provisional: r.provisional,
      // ORCS §4.3 attributes. Reconstructed only when the row carries a decision -- a row
      // written before the lifecycle existed has no `decidedAt`, and leaving `relationship`
      // undefined lets relationshipOf() apply the documented backfill rather than inventing
      // provenance here that nobody recorded.
      relationship: r.decidedAt
        ? {
            type: r.relationshipType as RelationshipType,
            purpose: r.relationshipPurpose ?? '',
            status: r.relationshipStatus as RelationshipStatus,
            validFrom: r.validFrom ? r.validFrom.toISOString() : r.createdAt.toISOString(),
            validTo: r.validTo ? r.validTo.toISOString() : undefined,
            policyVersion: r.policyVersion ?? '',
            evidenceRefs: r.evidenceRefs ?? [],
            assuranceProfileId: r.assuranceProfileId ?? undefined,
            issuer: r.relationshipIssuer ?? '',
            decidedBy: r.decidedBy ?? '',
            submittedBy: r.submittedBy ?? undefined,
            decidedAt: r.decidedAt.toISOString(),
            endedAt: r.endedAt ? r.endedAt.toISOString() : undefined,
            endedReason: r.endedReason ?? undefined,
            endedBy: r.endedBy ?? undefined,
          }
        : undefined,
      // ORCS §10 credential status. Reconstructed only when a decision was recorded; a row
      // with no `credentialStatusAt` predates this and is read through
      // backfilledCredentialStatus from whatever its revocation bit says.
      credentialStatus: r.credentialStatusAt
        ? {
            status: r.credentialStatus as CredentialStatus,
            reason: r.credentialReason ?? undefined,
            authority: r.credentialAuthority ?? undefined,
            at: r.credentialStatusAt.toISOString(),
            appealPath: r.appealPath ?? undefined,
            supersededBy: r.supersededBy ?? undefined,
          }
        : undefined,
      erasedAt: r.erasedAt ? r.erasedAt.toISOString() : undefined,
      credentialId: r.credentialId ?? undefined,
      statusListIndex: r.statusListIndex,
      createdAt: r.createdAt.toISOString(),
      person: {
        fullName: r.fullName ?? undefined,
        givenName: r.givenName ?? undefined,
        familyName: r.familyName ?? undefined,
        dateOfBirth: r.dateOfBirth ?? undefined,
        gender: r.gender ?? undefined,
      },
    };
  }

  /**
   * This person's residency in this deployment, if they hold one.
   *
   * `findUnique` because `subjectRef` is unique: one subnational government, one residency
   * per person. Relationships with other jurisdictions are held by those jurisdictions and
   * reach this deployment as credentials to verify, not as rows to store.
   */
  async findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null> {
    const r = await this.prisma.resident.findUnique({ where: { subjectRef } });
    return r ? this.toRecord(r) : null;
  }

  async findByResidentId(residentId: string): Promise<ResidentRecord | null> {
    const r = await this.prisma.resident.findUnique({ where: { residentId } });
    return r ? this.toRecord(r) : null;
  }

  /**
   * Destroy every identifying field, keeping the row.
   *
   * `statusListIndex` and `residentId` are deliberately not touched: reusing an erased
   * person's status index would hand their revocation bit to the next resident issued, and
   * the residentId is what keeps the revocation attributable.
   */
  async erase(residentId: string, tombstone: string, at: Date): Promise<ResidentRecord | null> {
    const existing = await this.prisma.resident.findUnique({ where: { residentId } });
    if (!existing) return null;
    const r = await this.prisma.resident.update({
      where: { residentId },
      data: {
        subjectRef: tombstone,
        fullName: null,
        givenName: null,
        familyName: null,
        dateOfBirth: null,
        gender: null,
        phoneHash: null,
        phoneEnc: null,
        erasedAt: at,
      },
    });
    return this.toRecord(r);
  }

  async nextStatusIndex(countryCode: string): Promise<number> {
    // Atomically reserve the next index for this country.
    //
    // The counter lives on the REVOCATION row and nowhere else. An index identifies a person
    // within the jurisdiction, and the same index means the same person in both lists -- so
    // incrementing per list would let a resident's revocation bit and suspension bit refer to
    // two different people, which is the worst failure this table can produce.
    const state = await this.prisma.statusListState.upsert({
      where: { countryCode_purpose: { countryCode, purpose: 'revocation' } },
      create: {
        countryCode,
        purpose: 'revocation',
        encodedList: new StatusList().encode(),
        nextIndex: 1,
      },
      update: { nextIndex: { increment: 1 } },
    });
    // nextIndex now points past the reserved slot; the reserved index is nextIndex-1.
    return state.nextIndex - 1;
  }

  /**
   * Write a record, creating it or updating it in place.
   *
   * An upsert rather than a create, because a record's relationship now changes after
   * issuance: a lifecycle transition rewrites its status, and a person who left and returned
   * is re-issued onto the same row (`subjectRef` is unique, so a second row is not an option).
   * A bare `create` threw on both. Keyed on `id`, which the service carries forward from the
   * existing record precisely so this lands on the right row.
   *
   * Every ORCS §4.3 column is set explicitly in both branches. A defaulted column that the
   * write path leaves out is silently overridden by its default, which is the third of the
   * three false greens recorded under G-01 -- a service that had decided one thing and a row
   * that ended up saying another.
   */
  async save(record: ResidentRecord): Promise<ResidentRecord> {
    const rel = record.relationship;
    const data = {
      residentId: record.residentId,
      subjectRef: record.subjectRef,
      countryCode: record.countryCode,
      subnationalUnit: record.subnationalUnit,
      providerCode: record.providerCode,
      assuranceLevel: record.assuranceLevel,
      bindingMethod: record.binding?.method ?? 'none',
      bindingRef: record.binding?.ref,
      bindingAt: record.binding?.verifiedAt ? new Date(record.binding.verifiedAt) : undefined,
      bindingScore: record.binding?.score,
      residenceAssurance: record.residence?.assuranceLevel ?? 'RAL0',
      residenceMethod: record.residence?.method ?? 'self_declared',
      residenceUnit: record.residence?.unit,
      residenceAsOf: record.residence?.asOf ? new Date(record.residence.asOf) : undefined,
      provisional: record.provisional,
      relationshipType: rel?.type ?? 'GENERAL_RESIDENCY',
      relationshipPurpose: rel?.purpose ?? '',
      relationshipStatus: rel?.status ?? 'ACTIVE',
      validFrom: rel?.validFrom ? new Date(rel.validFrom) : undefined,
      validTo: rel?.validTo ? new Date(rel.validTo) : null,
      policyVersion: rel?.policyVersion,
      evidenceRefs: rel?.evidenceRefs ?? [],
      assuranceProfileId: rel?.assuranceProfileId,
      relationshipIssuer: rel?.issuer,
      decidedBy: rel?.decidedBy,
      submittedBy: rel?.submittedBy ?? null,
      decidedAt: rel?.decidedAt ? new Date(rel.decidedAt) : undefined,
      endedAt: rel?.endedAt ? new Date(rel.endedAt) : null,
      endedReason: rel?.endedReason ?? null,
      endedBy: rel?.endedBy ?? null,
      credentialStatus: record.credentialStatus?.status ?? 'ACTIVE',
      credentialReason: record.credentialStatus?.reason ?? null,
      credentialAuthority: record.credentialStatus?.authority ?? null,
      credentialStatusAt: record.credentialStatus?.at
        ? new Date(record.credentialStatus.at)
        : undefined,
      appealPath: record.credentialStatus?.appealPath ?? null,
      supersededBy: record.credentialStatus?.supersededBy ?? null,
      credentialId: record.credentialId,
      statusListIndex: record.statusListIndex,
      fullName: record.person.fullName,
      givenName: record.person.givenName,
      familyName: record.person.familyName,
      dateOfBirth: record.person.dateOfBirth,
      gender: record.person.gender,
    };
    const r = await this.prisma.resident.upsert({
      where: { id: record.id },
      create: { id: record.id, ...data },
      update: data,
    });
    return this.toRecord(r);
  }

  async loadStatusList(
    countryCode: string,
    purpose: StatusPurpose = 'revocation',
  ): Promise<StatusList> {
    const state = await this.prisma.statusListState.findUnique({
      where: { countryCode_purpose: { countryCode, purpose } },
    });
    if (!state) return new StatusList();
    return StatusList.fromEncoded(state.encodedList);
  }

  async saveStatusList(
    countryCode: string,
    list: StatusList,
    purpose: StatusPurpose = 'revocation',
  ): Promise<void> {
    await this.prisma.statusListState.upsert({
      where: { countryCode_purpose: { countryCode, purpose } },
      create: { countryCode, purpose, encodedList: list.encode(), nextIndex: 0 },
      update: { encodedList: list.encode() },
    });
  }

  async list(opts?: {
    countryCode?: string;
    limit?: number;
    offset?: number;
    provisional?: boolean;
  }): Promise<{
    total: number;
    items: ResidentRecord[];
  }> {
    const where = {
      ...(opts?.countryCode ? { countryCode: opts.countryCode } : {}),
      ...(opts?.provisional !== undefined ? { provisional: opts.provisional } : {}),
    };
    const [total, rows] = await Promise.all([
      this.prisma.resident.count({ where }),
      this.prisma.resident.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: opts?.offset ?? 0,
        take: opts?.limit ?? 50,
      }),
    ]);
    return { total, items: rows.map((r) => this.toRecord(r)) };
  }

  // ---- contact data -------------------------------------------------------
  //
  // Kept off the ResidencyStore port on purpose. The core residency service has no reason
  // to touch contact details, and not handing it the capability is the cheapest way to
  // guarantee a phone number never reaches a credential or an audit record.

  /** The stored ciphertext for a resident's number, for the contact directory to decrypt. */
  async loadEncryptedContact(residentId: string): Promise<string | null> {
    const r = await this.prisma.resident.findUnique({
      where: { residentId },
      select: { phoneEnc: true },
    });
    return r?.phoneEnc ?? null;
  }

  /**
   * Record a resident's contact number: the hash for matching, and the ciphertext for
   * delivery. Both are derived by the caller, so this layer never sees a policy decision
   * about which of them a deployment is allowed to keep.
   */
  async setContact(
    residentId: string,
    phoneHash: string | null,
    phoneEnc: string | null,
  ): Promise<void> {
    await this.prisma.resident.update({
      where: { residentId },
      data: { phoneHash, phoneEnc },
    });
  }

  /** Resolve a resident by the hash of their phone number (the USSD entry point). */
  async findByPhoneHash(phoneHash: string): Promise<ResidentRecord | null> {
    const r = await this.prisma.resident.findFirst({ where: { phoneHash } });
    return r ? this.toRecord(r) : null;
  }
}

/** Prisma-backed audit store implementing the hash-chained AuditStore port. */
@Injectable()
export class PrismaAuditStore implements AuditStore {
  constructor(private prisma: PrismaService) {}

  async append(event: AuditEvent): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        seq: event.seq,
        eventId: event.id,
        timestamp: new Date(event.timestamp),
        action: event.action,
        actor: event.actor,
        target: event.target,
        countryCode: event.countryCode,
        outcome: event.outcome,
        metadata: (event.metadata ?? undefined) as any,
        prevHash: event.prevHash,
        hash: event.hash,
      },
    });
  }

  /**
   * Overwrite an event in place. Redaction only -- `record` never calls this.
   *
   * `hash` and `prevHash` are not in the update: the original hash is the commitment to what
   * the event said before redaction, and rewriting it would turn an auditable redaction into
   * an untraceable edit.
   */
  async replace(event: AuditEvent): Promise<void> {
    await this.prisma.auditEvent.update({
      where: { seq: event.seq },
      data: {
        actor: event.actor,
        target: event.target ?? null,
        metadata: (event.metadata ?? null) as any,
        redactedAt: event.redactedAt ? new Date(event.redactedAt) : null,
      },
    });
  }

  async tail(): Promise<{ seq: number; hash: string } | null> {
    const last = await this.prisma.auditEvent.findFirst({ orderBy: { seq: 'desc' } });
    return last ? { seq: last.seq, hash: last.hash } : null;
  }

  async list(opts?: { limit?: number; offset?: number; target?: string }): Promise<AuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({
      where: opts?.target ? { target: opts.target } : {},
      orderBy: { seq: 'desc' },
      skip: opts?.offset ?? 0,
      take: opts?.limit ?? 100,
    });
    return rows.map(this.toEvent);
  }

  async all(): Promise<AuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({ orderBy: { seq: 'asc' } });
    return rows.map(this.toEvent);
  }

  private toEvent = (r: any): AuditEvent => ({
    seq: r.seq,
    id: r.eventId,
    timestamp: r.timestamp.toISOString(),
    action: r.action,
    actor: r.actor,
    target: r.target ?? undefined,
    countryCode: r.countryCode ?? undefined,
    outcome: r.outcome,
    metadata: (r.metadata ?? undefined) as Record<string, unknown> | undefined,
    prevHash: r.prevHash,
    hash: r.hash,
    redactedAt: r.redactedAt ? r.redactedAt.toISOString() : undefined,
  });
}

/**
 * Prisma-backed OpenID4VCI store: credential offers and single-use nonces.
 *
 * This has to be a shared store rather than process memory, because the Kubernetes
 * manifests run several replicas behind a load balancer. A wallet creates its offer on
 * one pod and redeems it on whichever pod the load balancer picks next; in-memory state
 * would make issuance fail roughly (1 - 1/replicas) of the time.
 */
@Injectable()
export class PrismaOid4vciStore implements Oid4vciStore {
  constructor(private prisma: PrismaService) {}

  private toOffer = (r: any): CredentialOfferRecord => ({
    id: r.id,
    preAuthorizedCodeHash: r.preAuthorizedCodeHash,
    txCodeHash: r.txCodeHash ?? undefined,
    residentId: r.residentId,
    countryCode: r.countryCode,
    credentialConfigurationIds: r.configurationIds,
    expiresAt: r.expiresAt.toISOString(),
    redeemedAt: r.redeemedAt ? r.redeemedAt.toISOString() : undefined,
    failedAttempts: r.failedAttempts,
    createdAt: r.createdAt.toISOString(),
  });

  async saveOffer(offer: CredentialOfferRecord): Promise<void> {
    await this.prisma.credentialOffer.create({
      data: {
        id: offer.id,
        preAuthorizedCodeHash: offer.preAuthorizedCodeHash,
        txCodeHash: offer.txCodeHash,
        residentId: offer.residentId,
        countryCode: offer.countryCode,
        configurationIds: offer.credentialConfigurationIds,
        expiresAt: new Date(offer.expiresAt),
        failedAttempts: offer.failedAttempts,
      },
    });
  }

  async findOfferById(id: string): Promise<CredentialOfferRecord | null> {
    const r = await this.prisma.credentialOffer.findUnique({ where: { id } });
    return r ? this.toOffer(r) : null;
  }

  async findOfferByCodeHash(codeHash: string): Promise<CredentialOfferRecord | null> {
    const r = await this.prisma.credentialOffer.findUnique({
      where: { preAuthorizedCodeHash: codeHash },
    });
    return r ? this.toOffer(r) : null;
  }

  async updateOffer(offer: CredentialOfferRecord): Promise<void> {
    await this.prisma.credentialOffer.update({
      where: { id: offer.id },
      data: {
        redeemedAt: offer.redeemedAt ? new Date(offer.redeemedAt) : null,
        failedAttempts: offer.failedAttempts,
      },
    });
  }

  async saveNonce(nonce: NonceRecord): Promise<void> {
    await this.prisma.oid4vciNonce.create({
      data: { nonceHash: nonce.nonceHash, expiresAt: new Date(nonce.expiresAt) },
    });
  }

  /**
   * Consume a nonce, atomically.
   *
   * A read-then-delete would race: two concurrent credential requests carrying the same
   * captured key proof could both observe the nonce as unused before either deleted it,
   * and both would be issued a credential -- which is precisely the replay this nonce
   * exists to prevent. A conditional DELETE is atomic in PostgreSQL, so exactly one
   * caller sees a non-zero count.
   */
  async consumeNonce(nonceHash: string): Promise<boolean> {
    const { count } = await this.prisma.oid4vciNonce.deleteMany({
      where: { nonceHash, expiresAt: { gt: new Date() } },
    });
    return count === 1;
  }
}

/** Prisma-backed OpenID4VP store: in-flight presentation requests. */
@Injectable()
export class PrismaOid4vpStore implements Oid4vpStore {
  constructor(private prisma: PrismaService) {}

  private toRecord = (r: any): PresentationRequestRecord => ({
    id: r.id,
    nonce: r.nonce,
    clientId: r.clientId,
    purpose: r.purpose,
    reference: r.reference ?? undefined,
    status: r.status,
    outcome: (r.outcome ?? undefined) as Record<string, unknown> | undefined,
    expiresAt: r.expiresAt.toISOString(),
    createdAt: r.createdAt.toISOString(),
  });

  async saveRequest(request: PresentationRequestRecord): Promise<void> {
    await this.prisma.presentationRequest.create({
      data: {
        id: request.id,
        nonce: request.nonce,
        clientId: request.clientId,
        purpose: request.purpose,
        reference: request.reference,
        status: request.status,
        expiresAt: new Date(request.expiresAt),
      },
    });
  }

  async findRequest(id: string): Promise<PresentationRequestRecord | null> {
    const r = await this.prisma.presentationRequest.findUnique({ where: { id } });
    return r ? this.toRecord(r) : null;
  }

  /**
   * Record an outcome only while the request is still pending.
   *
   * The `status: 'pending'` predicate is the point. A plain update would let a captured
   * vp_token be posted twice: the second POST would re-verify and overwrite the verdict,
   * so a presentation would not be single-use. A conditional UPDATE is atomic in
   * PostgreSQL, so exactly one caller sees a non-zero count and the rest are told the
   * request was already answered.
   */
  async completeRequest(
    id: string,
    status: 'fulfilled' | 'failed',
    outcome: Record<string, unknown>,
  ): Promise<boolean> {
    const { count } = await this.prisma.presentationRequest.updateMany({
      where: { id, status: 'pending' },
      data: { status, outcome: outcome as any },
    });
    return count === 1;
  }
}

/**
 * Prisma-backed store for the OIDC provider's own state.
 *
 * Replaces oidc-provider's development in-memory adapter, which cannot serve a deployment
 * running more than one replica -- see the port in `src/core/sso/oidc-store.ts` for why the
 * resulting sign-in failure is intermittent rather than obvious.
 */
@Injectable()
export class PrismaOidcStore implements OidcStore {
  constructor(private prisma: PrismaService) {}

  private toItem = (r: any): OidcStoredItem => ({
    name: r.name,
    id: r.id,
    payload: (r.payload ?? {}) as Record<string, unknown>,
    grantId: r.grantId,
    uid: r.uid,
    userCode: r.userCode,
    expiresAt: r.expiresAt,
    consumedAt: r.consumedAt,
  });

  /**
   * A row is only live while unexpired. Expressed as a `where` clause rather than filtered
   * after the read so the database never hands back a token that has already lapsed, even
   * if the sweep is behind.
   */
  private static unexpired(now: Date) {
    return { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] };
  }

  async upsert(item: OidcStoredItem): Promise<void> {
    const data = {
      payload: item.payload as any,
      grantId: item.grantId ?? null,
      uid: item.uid ?? null,
      userCode: item.userCode ?? null,
      expiresAt: item.expiresAt ?? null,
    };
    // `consumedAt` is deliberately absent from the update branch: oidc-provider re-upserts
    // an existing id to extend it, and clearing the consumed marker there would make a
    // spent authorization code replayable.
    await this.prisma.oidcStoredItem.upsert({
      where: { name_id: { name: item.name, id: item.id } },
      create: { name: item.name, id: item.id, ...data, consumedAt: item.consumedAt ?? null },
      update: data,
    });
  }

  async find(name: string, id: string, now: Date): Promise<OidcStoredItem | null> {
    const r = await this.prisma.oidcStoredItem.findFirst({
      where: { name, id, ...PrismaOidcStore.unexpired(now) },
    });
    return r ? this.toItem(r) : null;
  }

  async findByUid(name: string, uid: string, now: Date): Promise<OidcStoredItem | null> {
    const r = await this.prisma.oidcStoredItem.findFirst({
      where: { name, uid, ...PrismaOidcStore.unexpired(now) },
    });
    return r ? this.toItem(r) : null;
  }

  async findByUserCode(name: string, userCode: string, now: Date): Promise<OidcStoredItem | null> {
    const r = await this.prisma.oidcStoredItem.findFirst({
      where: { name, userCode, ...PrismaOidcStore.unexpired(now) },
    });
    return r ? this.toItem(r) : null;
  }

  async consume(name: string, id: string, at: Date): Promise<void> {
    await this.prisma.oidcStoredItem.updateMany({
      where: { name, id },
      data: { consumedAt: at },
    });
  }

  async destroy(name: string, id: string): Promise<void> {
    await this.prisma.oidcStoredItem.deleteMany({ where: { name, id } });
  }

  async revokeByGrantId(name: string, grantId: string): Promise<void> {
    await this.prisma.oidcStoredItem.deleteMany({ where: { name, grantId } });
  }

  async purgeExpired(now: Date): Promise<number> {
    const { count } = await this.prisma.oidcStoredItem.deleteMany({
      where: { expiresAt: { not: null, lte: now } },
    });
    return count;
  }
}

/**
 * Prisma-backed store for refused applications.
 *
 * The read paths are by reference and by tokenized subject only. There is deliberately no
 * "list all refusals" method: a refusal log is a record each applicant can consult about
 * themselves, not a roster of people the deployment turned away.
 */
@Injectable()
export class PrismaRefusalStore implements RefusalStore {
  constructor(private prisma: PrismaService) {}

  private toRecord = (r: any): RefusalRecord => ({
    reference: r.reference,
    countryCode: r.countryCode,
    subnationalUnit: r.subnationalUnit,
    subjectRef: r.subjectRef ?? undefined,
    reason: r.reason,
    decidedBy: r.decidedBy,
    submittedBy: r.submittedBy ?? undefined,
    appealPath: r.appealPath,
    humanReviewPath: r.humanReviewPath ?? undefined,
    reviewStatus: (r.reviewStatus ?? 'none') as ReviewStatus,
    reviewedBy: r.reviewedBy ?? undefined,
    reviewedAt: r.reviewedAt ? r.reviewedAt.toISOString() : undefined,
    reviewNote: r.reviewNote ?? undefined,
    refusedAt: r.refusedAt.toISOString(),
  });

  async save(record: RefusalRecord): Promise<RefusalRecord> {
    const r = await this.prisma.residencyRefusal.create({
      data: {
        reference: record.reference,
        countryCode: record.countryCode,
        subnationalUnit: record.subnationalUnit,
        subjectRef: record.subjectRef ?? null,
        reason: record.reason,
        decidedBy: record.decidedBy,
        submittedBy: record.submittedBy ?? null,
        appealPath: record.appealPath,
        humanReviewPath: record.humanReviewPath ?? null,
        reviewStatus: record.reviewStatus,
        refusedAt: new Date(record.refusedAt),
      },
    });
    return this.toRecord(r);
  }

  async findByReference(reference: string): Promise<RefusalRecord | null> {
    const r = await this.prisma.residencyRefusal.findUnique({ where: { reference } });
    return r ? this.toRecord(r) : null;
  }

  async listBySubjectRef(subjectRef: string): Promise<RefusalRecord[]> {
    const rows = await this.prisma.residencyRefusal.findMany({
      where: { subjectRef },
      orderBy: { refusedAt: 'desc' },
    });
    return rows.map(this.toRecord);
  }

  async recordReview(
    reference: string,
    review: { status: ReviewStatus; by: string; at: string; note?: string },
  ): Promise<RefusalRecord | null> {
    const existing = await this.prisma.residencyRefusal.findUnique({ where: { reference } });
    if (!existing) return null;
    const r = await this.prisma.residencyRefusal.update({
      where: { reference },
      data: {
        reviewStatus: review.status,
        reviewedBy: review.by,
        reviewedAt: new Date(review.at),
        reviewNote: review.note ?? null,
      },
    });
    return this.toRecord(r);
  }
}

/** Prisma-backed OTP store for the sign-in fallback factor. */
@Injectable()
export class PrismaOtpStore implements OtpStore {
  constructor(private prisma: PrismaService) {}

  private toRecord = (r: any): OtpChallengeRecord => ({
    id: r.id,
    residentId: r.residentId,
    codeHash: r.codeHash,
    channel: r.channel,
    expiresAt: r.expiresAt.toISOString(),
    consumed: r.consumed,
    failedAttempts: r.failedAttempts,
    createdAt: r.createdAt.toISOString(),
  });

  async save(challenge: OtpChallengeRecord): Promise<void> {
    await this.prisma.otpChallenge.create({
      data: {
        id: challenge.id,
        residentId: challenge.residentId,
        codeHash: challenge.codeHash,
        channel: challenge.channel,
        expiresAt: new Date(challenge.expiresAt),
        consumed: challenge.consumed,
        failedAttempts: challenge.failedAttempts,
      },
    });
  }

  async findActive(residentId: string): Promise<OtpChallengeRecord | null> {
    const r = await this.prisma.otpChallenge.findFirst({
      where: { residentId, consumed: false },
      orderBy: { createdAt: 'desc' },
    });
    return r ? this.toRecord(r) : null;
  }

  async recentFor(residentId: string, since: string): Promise<OtpChallengeRecord[]> {
    // Consumed challenges are included deliberately: a successful sign-in does not erase
    // the failures that preceded it, and excluding them would let an attacker clear the
    // window by completing one login.
    const rows = await this.prisma.otpChallenge.findMany({
      where: { residentId, createdAt: { gte: new Date(since) } },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.toRecord(r));
  }

  async update(challenge: OtpChallengeRecord): Promise<void> {
    await this.prisma.otpChallenge.update({
      where: { id: challenge.id },
      data: {
        channel: challenge.channel,
        consumed: challenge.consumed,
        failedAttempts: challenge.failedAttempts,
      },
    });
  }
}

/**
 * Prisma-backed record of which legal bases have been withdrawn.
 *
 * Only withdrawals are stored. Which bases exist is declared in the jurisdiction config and
 * rebuilt at boot, so persisting the definitions too would create a second source of truth
 * able to disagree with the config -- and the config is the one a reviewer reads.
 */
@Injectable()
export class PrismaLegalBasisStore implements LegalBasisStore {
  constructor(private prisma: PrismaService) {}

  async listDeactivations(): Promise<LegalBasisDeactivation[]> {
    const rows = await this.prisma.legalBasis.findMany({ where: { NOT: { deactivatedAt: null } } });
    return rows.map((r) => ({
      id: r.id,
      deactivatedAt: r.deactivatedAt!.toISOString(),
      deactivationReason: r.deactivationReason ?? '',
      deactivatedBy: r.deactivatedBy ?? '',
    }));
  }

  async saveDeactivation(record: LegalBasisDeactivation & Partial<LegalBasis>): Promise<void> {
    const definition = {
      kind: record.kind ?? '',
      name: record.name ?? '',
      instrument: record.instrument ?? '',
      jurisdiction: record.jurisdiction ?? '',
      controller: record.controller ?? '',
      version: record.version ?? '',
      effectiveFrom: record.effectiveFrom ? new Date(record.effectiveFrom) : new Date(0),
      effectiveTo: record.effectiveTo ? new Date(record.effectiveTo) : null,
    };
    const withdrawal = {
      deactivatedAt: new Date(record.deactivatedAt),
      deactivationReason: record.deactivationReason,
      deactivatedBy: record.deactivatedBy,
    };
    await this.prisma.legalBasis.upsert({
      where: { id: record.id },
      create: { id: record.id, ...definition, ...withdrawal },
      // The definition is not rewritten on update: it came from the config at boot, and the
      // config is authoritative for what the basis says. Only the withdrawal is ours to record.
      update: withdrawal,
    });
  }
}

/** Prisma-backed consent store. */
@Injectable()
export class PrismaConsentStore implements ConsentStore {
  constructor(private prisma: PrismaService) {}

  private toRecord = (r: any): ConsentRecord => ({
    id: r.id,
    subjectRef: r.subjectRef,
    residentId: r.residentId,
    relyingParty: r.relyingParty,
    relyingPartyName: r.relyingPartyName ?? undefined,
    purpose: r.purpose,
    scopes: r.scopes,
    status: r.status,
    grantedAt: r.grantedAt.toISOString(),
    expiresAt: r.expiresAt ? r.expiresAt.toISOString() : undefined,
    revokedAt: r.revokedAt ? r.revokedAt.toISOString() : undefined,
    receiptId: r.receiptId,
    grantId: r.grantId ?? undefined,
    controller: r.controller ?? '',
    processor: r.processor ?? undefined,
    dataCategories: r.dataCategories ?? [],
    legalBasisReference: r.legalBasisReference ?? '',
    // A row written before the §9 columns existed has no evidence, and is reported as
    // `unrecorded` rather than as some method nobody used. The distinction matters because
    // `toData` writes this record straight back on the ordinary read paths that transition a
    // lapsed grant -- so any placeholder chosen here would be PERSISTED, backfilling exactly
    // the evidence the migration deliberately declined to invent. `unrecorded` round-trips to
    // an empty column, so reading a legacy row never turns it into a claim.
    evidence: {
      method: (r.evidenceMethod || 'unrecorded') as ConsentRecord['evidence']['method'],
      at: r.evidenceAt ? r.evidenceAt.toISOString() : r.grantedAt.toISOString(),
      reference: r.evidenceReference ?? '',
      capturedBy: r.evidenceCapturedBy ?? undefined,
    },
    version: r.version ?? 1,
    supersedesId: r.supersedesId ?? undefined,
    supersededById: r.supersededById ?? undefined,
    withdrawnBy: r.withdrawnBy ?? undefined,
  });

  async save(record: ConsentRecord): Promise<ConsentRecord> {
    const r = await this.prisma.consentRecord.create({ data: this.toData(record) });
    return this.toRecord(r);
  }
  async findById(id: string): Promise<ConsentRecord | null> {
    const r = await this.prisma.consentRecord.findUnique({ where: { id } });
    return r ? this.toRecord(r) : null;
  }
  async findActive(residentId: string, relyingParty: string): Promise<ConsentRecord | null> {
    const r = await this.prisma.consentRecord.findFirst({
      where: { residentId, relyingParty, status: 'active' },
      orderBy: { grantedAt: 'desc' },
    });
    return r ? this.toRecord(r) : null;
  }
  async listByResident(residentId: string): Promise<ConsentRecord[]> {
    const rows = await this.prisma.consentRecord.findMany({
      where: { residentId },
      orderBy: { grantedAt: 'desc' },
    });
    return rows.map(this.toRecord);
  }
  async update(record: ConsentRecord): Promise<ConsentRecord> {
    const r = await this.prisma.consentRecord.update({
      where: { id: record.id },
      data: this.toData(record),
    });
    return this.toRecord(r);
  }

  private toData(record: ConsentRecord) {
    return {
      id: record.id,
      subjectRef: record.subjectRef,
      residentId: record.residentId,
      relyingParty: record.relyingParty,
      relyingPartyName: record.relyingPartyName,
      purpose: record.purpose,
      scopes: record.scopes,
      status: record.status,
      grantedAt: new Date(record.grantedAt),
      expiresAt: record.expiresAt ? new Date(record.expiresAt) : null,
      revokedAt: record.revokedAt ? new Date(record.revokedAt) : null,
      receiptId: record.receiptId,
      grantId: record.grantId ?? null,
      controller: record.controller,
      processor: record.processor ?? null,
      dataCategories: record.dataCategories,
      legalBasisReference: record.legalBasisReference,
      // `unrecorded` is the read-side marker for a legacy row and must not become a stored
      // value: writing it back would turn "we never captured this" into a recorded method.
      evidenceMethod: record.evidence.method === 'unrecorded' ? '' : record.evidence.method,
      evidenceAt: record.evidence.method === 'unrecorded' ? null : new Date(record.evidence.at),
      evidenceReference: record.evidence.reference,
      evidenceCapturedBy: record.evidence.capturedBy ?? null,
      version: record.version,
      supersedesId: record.supersedesId ?? null,
      supersededById: record.supersededById ?? null,
      withdrawnBy: record.withdrawnBy ?? null,
    };
  }
}

/**
 * Prisma-backed OperatorStore: the staff identities behind privileged actions.
 *
 * Nothing here stores a presentable credential. Passwords are scrypt hashes and API keys
 * are SHA-256 hashes, so a dump of these two tables yields nothing that can be used to
 * authenticate.
 */
@Injectable()
export class PrismaOperatorStore implements OperatorStore {
  constructor(private prisma: PrismaService) {}

  private toRecord = (r: any): OperatorRecord => ({
    id: r.id,
    email: r.email,
    displayName: r.displayName,
    roles: r.roles,
    passwordHash: r.passwordHash,
    totpSecret: r.totpSecret,
    totpConfirmedAt: r.totpConfirmedAt ? r.totpConfirmedAt.toISOString() : null,
    failedLogins: r.failedLogins,
    lockedUntil: r.lockedUntil ? r.lockedUntil.toISOString() : null,
    disabledAt: r.disabledAt ? r.disabledAt.toISOString() : null,
    createdAt: r.createdAt.toISOString(),
  });

  private toKey = (r: any): OperatorKeyRecord => ({
    id: r.id,
    operatorId: r.operatorId,
    label: r.label,
    keyHash: r.keyHash,
    expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
    lastUsedAt: r.lastUsedAt ? r.lastUsedAt.toISOString() : null,
    revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
    rotatedFrom: r.rotatedFrom,
    createdAt: r.createdAt.toISOString(),
  });

  async findById(id: string): Promise<OperatorRecord | null> {
    const r = await this.prisma.operator.findUnique({ where: { id } });
    return r ? this.toRecord(r) : null;
  }

  async findByEmail(email: string): Promise<OperatorRecord | null> {
    const r = await this.prisma.operator.findUnique({ where: { email } });
    return r ? this.toRecord(r) : null;
  }

  async list(): Promise<OperatorRecord[]> {
    const rows = await this.prisma.operator.findMany({ orderBy: { createdAt: 'asc' } });
    return rows.map(this.toRecord);
  }

  async count(): Promise<number> {
    return this.prisma.operator.count();
  }

  async create(record: OperatorRecord): Promise<void> {
    await this.prisma.operator.create({
      data: {
        id: record.id,
        email: record.email,
        displayName: record.displayName,
        roles: record.roles,
        passwordHash: record.passwordHash,
        totpSecret: record.totpSecret,
        totpConfirmedAt: record.totpConfirmedAt ? new Date(record.totpConfirmedAt) : null,
        failedLogins: record.failedLogins,
        lockedUntil: record.lockedUntil ? new Date(record.lockedUntil) : null,
        disabledAt: record.disabledAt ? new Date(record.disabledAt) : null,
      },
    });
  }

  async update(record: OperatorRecord): Promise<void> {
    await this.prisma.operator.update({
      where: { id: record.id },
      data: {
        displayName: record.displayName,
        roles: record.roles,
        passwordHash: record.passwordHash,
        totpSecret: record.totpSecret,
        totpConfirmedAt: record.totpConfirmedAt ? new Date(record.totpConfirmedAt) : null,
        failedLogins: record.failedLogins,
        lockedUntil: record.lockedUntil ? new Date(record.lockedUntil) : null,
        disabledAt: record.disabledAt ? new Date(record.disabledAt) : null,
      },
    });
  }

  async findKeyByHash(keyHash: string): Promise<OperatorKeyRecord | null> {
    const r = await this.prisma.operatorKey.findUnique({ where: { keyHash } });
    return r ? this.toKey(r) : null;
  }

  async findKeyById(id: string): Promise<OperatorKeyRecord | null> {
    const r = await this.prisma.operatorKey.findUnique({ where: { id } });
    return r ? this.toKey(r) : null;
  }

  async listKeys(operatorId: string): Promise<OperatorKeyRecord[]> {
    const rows = await this.prisma.operatorKey.findMany({
      where: { operatorId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(this.toKey);
  }

  async createKey(record: OperatorKeyRecord): Promise<void> {
    await this.prisma.operatorKey.create({
      data: {
        id: record.id,
        operatorId: record.operatorId,
        label: record.label,
        keyHash: record.keyHash,
        expiresAt: record.expiresAt ? new Date(record.expiresAt) : null,
        rotatedFrom: record.rotatedFrom,
      },
    });
  }

  async updateKey(record: OperatorKeyRecord): Promise<void> {
    await this.prisma.operatorKey.update({
      where: { id: record.id },
      data: {
        label: record.label,
        expiresAt: record.expiresAt ? new Date(record.expiresAt) : null,
        lastUsedAt: record.lastUsedAt ? new Date(record.lastUsedAt) : null,
        revokedAt: record.revokedAt ? new Date(record.revokedAt) : null,
      },
    });
  }
}

@Injectable()
export class PrismaWebAuthnChallengeStore implements WebAuthnChallengeStore {
  constructor(private prisma: PrismaService) {}

  async save(r: WebAuthnChallengeRecord): Promise<void> {
    await this.prisma.webAuthnChallenge.create({
      data: {
        id: r.id,
        residentId: r.residentId,
        challenge: r.challenge,
        purpose: r.purpose,
        expiresAt: new Date(r.expiresAt),
        consumed: r.consumed,
      },
    });
  }

  async findActive(id: string): Promise<WebAuthnChallengeRecord | null> {
    const r = await this.prisma.webAuthnChallenge.findUnique({ where: { id } });
    if (!r) return null;
    return {
      id: r.id,
      residentId: r.residentId,
      challenge: r.challenge,
      purpose: r.purpose as 'register' | 'authenticate',
      expiresAt: r.expiresAt.toISOString(),
      consumed: r.consumed,
      createdAt: r.createdAt.toISOString(),
    };
  }

  async consume(id: string): Promise<void> {
    await this.prisma.webAuthnChallenge.update({ where: { id }, data: { consumed: true } });
  }
}

@Injectable()
export class PrismaWebAuthnCredentialStore implements WebAuthnCredentialStore {
  constructor(private prisma: PrismaService) {}

  private toStored = (r: any): StoredCredential => ({
    id: r.id,
    credentialId: r.credentialId,
    residentId: r.residentId,
    publicJwk: r.publicJwk as JWK,
    alg: r.alg as WebAuthnAlg,
    signCount: r.signCount,
    createdAt: r.createdAt.toISOString(),
    lastUsedAt: r.lastUsedAt ? r.lastUsedAt.toISOString() : undefined,
  });

  async add(c: StoredCredential): Promise<void> {
    await this.prisma.webAuthnCredential.create({
      data: {
        id: c.id,
        credentialId: c.credentialId,
        residentId: c.residentId,
        publicJwk: c.publicJwk as object,
        alg: c.alg,
        signCount: c.signCount,
      },
    });
  }

  async listForResident(residentId: string): Promise<StoredCredential[]> {
    const rows = await this.prisma.webAuthnCredential.findMany({ where: { residentId } });
    return rows.map(this.toStored);
  }

  async findByCredentialId(credentialId: string): Promise<StoredCredential | null> {
    const r = await this.prisma.webAuthnCredential.findUnique({ where: { credentialId } });
    return r ? this.toStored(r) : null;
  }

  async updateSignCount(credentialId: string, signCount: number, lastUsedAt: string): Promise<void> {
    await this.prisma.webAuthnCredential.update({
      where: { credentialId },
      data: { signCount, lastUsedAt: new Date(lastUsedAt) },
    });
  }
}

/**
 * Pending authorizations at an external OpenID Provider.
 *
 * Backed by a table because the two halves of the redirect are separate HTTP requests that
 * will not land on the same replica. `take` is a DELETE ... RETURNING rather than a read
 * followed by a write, which is what the port asks for: read-then-delete has a window in
 * which two concurrent callbacks both read the same row and both succeed, and single use is
 * the entire reason `state` defends anything.
 */
@Injectable()
export class PrismaUpstreamAuthStore implements PendingUpstreamAuthStore {
  constructor(private prisma: PrismaService) {}

  async put(auth: PendingUpstreamAuth): Promise<void> {
    await this.prisma.upstreamAuthRequest.create({
      data: {
        state: auth.state,
        nonce: auth.nonce,
        codeVerifier: auth.codeVerifier,
        createdAt: new Date(auth.createdAt),
      },
    });
  }

  async take(state: string): Promise<PendingUpstreamAuth | null> {
    try {
      const r = await this.prisma.upstreamAuthRequest.delete({ where: { state } });
      return {
        state: r.state,
        nonce: r.nonce,
        codeVerifier: r.codeVerifier,
        createdAt: r.createdAt.toISOString(),
      };
    } catch {
      // Prisma throws when the row is absent, which is the ordinary case for a replayed or
      // forged callback. That is a miss, not a fault.
      return null;
    }
  }

  /** Drop authorizations the resident abandoned at the OP. */
  async purgeOlderThan(cutoff: Date): Promise<number> {
    const { count } = await this.prisma.upstreamAuthRequest.deleteMany({
      where: { createdAt: { lt: cutoff } },
    });
    return count;
  }
}
