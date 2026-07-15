import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { StatusList } from '../core/credentials/status-list';
import { ResidencyStore, ResidentRecord } from '../core/residency/ports';
import { AuditEvent, AuditStore } from '../core/audit/audit-log';
import { ConsentRecord, ConsentStore } from '../core/consent/consent';
import { CredentialOfferRecord, NonceRecord, Oid4vciStore } from '../core/oid4vci/ports';
import { Oid4vpStore, PresentationRequestRecord } from '../core/oid4vp/ports';
import { OtpChallengeRecord, OtpStore } from '../core/sso/otp';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
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
      provisional: r.provisional,
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

  async findBySubjectRef(subjectRef: string): Promise<ResidentRecord | null> {
    const r = await this.prisma.resident.findUnique({ where: { subjectRef } });
    return r ? this.toRecord(r) : null;
  }

  async findByResidentId(residentId: string): Promise<ResidentRecord | null> {
    const r = await this.prisma.resident.findUnique({ where: { residentId } });
    return r ? this.toRecord(r) : null;
  }

  async nextStatusIndex(countryCode: string): Promise<number> {
    // Atomically reserve the next index for this country.
    const state = await this.prisma.statusListState.upsert({
      where: { countryCode },
      create: {
        countryCode,
        encodedList: new StatusList().encode(),
        nextIndex: 1,
      },
      update: { nextIndex: { increment: 1 } },
    });
    // nextIndex now points past the reserved slot; the reserved index is nextIndex-1.
    return state.nextIndex - 1;
  }

  async save(record: ResidentRecord): Promise<ResidentRecord> {
    const r = await this.prisma.resident.create({
      data: {
        id: record.id,
        residentId: record.residentId,
        subjectRef: record.subjectRef,
        countryCode: record.countryCode,
        subnationalUnit: record.subnationalUnit,
        providerCode: record.providerCode,
        assuranceLevel: record.assuranceLevel,
        provisional: record.provisional,
        credentialId: record.credentialId,
        statusListIndex: record.statusListIndex,
        fullName: record.person.fullName,
        givenName: record.person.givenName,
        familyName: record.person.familyName,
        dateOfBirth: record.person.dateOfBirth,
        gender: record.person.gender,
      },
    });
    return this.toRecord(r);
  }

  async loadStatusList(countryCode: string): Promise<StatusList> {
    const state = await this.prisma.statusListState.findUnique({ where: { countryCode } });
    if (!state) return new StatusList();
    return StatusList.fromEncoded(state.encodedList);
  }

  async saveStatusList(countryCode: string, list: StatusList): Promise<void> {
    await this.prisma.statusListState.upsert({
      where: { countryCode },
      create: { countryCode, encodedList: list.encode(), nextIndex: 0 },
      update: { encodedList: list.encode() },
    });
  }

  async list(opts?: { countryCode?: string; limit?: number; offset?: number }): Promise<{
    total: number;
    items: ResidentRecord[];
  }> {
    const where = opts?.countryCode ? { countryCode: opts.countryCode } : {};
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
    };
  }
}
