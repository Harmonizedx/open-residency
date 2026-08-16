// SPDX-License-Identifier: Apache-2.0
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { createHash } from 'node:crypto';
import {
  OperatorGuard,
  RequireRoles,
  RequestWithOperator,
  requireOperator,
} from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
import { encryptContact } from '../core/messaging/contact-directory';
import { PlatformService } from '../platform/platform.service';
import { residentIdPattern } from '../core/residency/resident-id';
import {
  CredentialTransitionDto,
  IssueDto,
  TransitionRelationshipDto,
  VerifyDto,
} from './dto/residency.dto';

// Request DTOs (validated by the global ValidationPipe) live in ./dto/residency.dto.ts.
// The trust requirements the old inline docs described still hold: `binding` and
// `residenceEvidence` are only meaningful from an authenticated operator context (this
// endpoint sits behind OperatorGuard), and `phone` handling is governed by
// contactDirectory.mode and never written to the credential, audit log, or any response.

/**
 * Public residency API. Note there is no country-specific code here: the controller
 * only resolves a CountryConfig and delegates to the generic ResidencyService.
 */
@Controller('residency')
export class ResidencyController {
  constructor(private platform: PlatformService) {}

  /** Which countries this deployment serves, and what inputs each foundational check needs. */
  @Get('countries')
  countries() {
    return this.platform.listConfigs().map((c) => ({
      countryCode: c.countryCode,
      countryName: c.countryName,
      provider: c.foundational.provider,
      inputs: c.foundational.inputs,
      subnationalUnits: c.subnationalUnits,
      // Applicant->identity binding policy, so an enrolment UI knows whether an operator
      // must attest binding and which methods this jurisdiction accepts.
      applicantBinding: c.residency.applicantBinding,
      // True when the foundational provider authenticates the owner itself (OTP / eID),
      // so the desk does not need to bind the applicant manually.
      authenticatesApplicant: c.foundational.authenticatesApplicant,
      // The resident id format this jurisdiction issues, plus a validation regex an MDA
      // system or capture UI can use without reimplementing the rules.
      residentIdFormat: c.residentId,
      residentIdPattern: residentIdPattern(c.residentId),
    }));
  }

  /**
   * Issue a residency credential for an applicant.
   *
   * Admin-guarded, for the same reason `revoke` is: minting a credential in someone's
   * name is at least as privileged as cancelling one. Two of this endpoint's own inputs
   * say so directly -- `binding` and `residenceEvidence` are documented above as only
   * meaningful from an authenticated operator context, because a caller who can post
   * their own `authority_attestation` is attesting their own residence, and one who can
   * self-assert `binding` clears the proofing bar a jurisdiction set at RAL2 without an
   * operator ever having looked at them.
   *
   * The audit entry names the operator who performed the enrolment, which is what makes
   * an attested binding meaningful after the fact: "an operator vouched for this person"
   * is only useful if you can say which one.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('issue')
  async issue(@Req() req: RequestWithOperator, @Body() body: IssueDto) {
    const operator = requireOperator(req);
    const cfg = this.platform.getConfig(body.countryCode);
    if (!cfg) throw new NotFoundException(`No config for country ${body.countryCode}`);

    const result = await this.platform.getResidency().issue(cfg, {
      countryCode: body.countryCode,
      subnationalUnit: body.subnationalUnit,
      identifiers: body.identifiers,
      holderId: body.holderId,
      challengeRef: body.challengeRef,
      proofOfResidence: body.proofOfResidence,
      binding: body.binding,
      residenceEvidence: body.residenceEvidence,
      // ORCS §4.3 decision provenance: the record names the operator who actually decided,
      // not a generic marker. The audit entry below names the same actor.
      decidedBy: operatorActor(operator),
      context: { offline: body.offline === true },
    });

    // Contact capture, once we know which resident this is. Deliberately after issuance
    // and non-fatal: a phone number that cannot be stored must not cost the applicant
    // their credential.
    if (body.phone && 'residentId' in result && result.residentId) {
      await this.recordContact(result.residentId, body.phone);
    }

    await this.platform.getAudit().record({
      action: 'residency.issue',
      actor: operatorActor(operator),
      target: 'residentId' in result ? result.residentId : undefined,
      countryCode: cfg.countryCode,
      outcome: result.status === 'issued' || result.status === 'exists' ? 'success' : 'failure',
      metadata: {
        status: result.status,
        subnationalUnit: body.subnationalUnit,
        // Record which binding method was achieved (or why issuance was refused) so the
        // proofing decision is auditable, not just the pass/fail outcome.
        bindingMethod: result.status === 'issued' ? result.record.binding.method : undefined,
        reason: result.status === 'rejected' ? result.reason : undefined,
      },
    });
    return result;
  }

  /**
   * Store what this deployment is configured to keep of a contact number.
   *
   * The hash is always kept: it is what USSD matching and duplicate detection use, and it
   * cannot be dialled or reversed. The ciphertext is kept only under
   * `contactDirectory.mode: encrypted`, because that is the only mode where this system is
   * the one that has to place the call.
   */
  private async recordContact(residentId: string, phone: string): Promise<void> {
    const e164 = phone.trim();
    if (!/^\+[1-9]\d{6,14}$/.test(e164)) return; // not E.164; keep nothing rather than guess
    const phoneHash = createHash('sha256').update(e164).digest('hex');
    const mode = this.platform.contactDirectoryMode();
    try {
      await this.platform
        .getStore()
        .setContact(residentId, phoneHash, mode === 'encrypted' ? encryptContact(e164) : null);
    } catch {
      // Never fail an issuance over contact storage.
    }
  }

  @Get(':residentId')
  async lookup(@Param('residentId') residentId: string) {
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    // Return non-sensitive residency status only.
    return {
      residentId: record.residentId,
      countryCode: record.countryCode,
      subnationalUnit: record.subnationalUnit,
      assuranceLevel: record.assuranceLevel,
      provisional: record.provisional,
      createdAt: record.createdAt,
    };
  }

  /**
   * Revoke a residency credential.
   *
   * Admin-guarded: revocation is a privileged, destructive act on someone else's identity,
   * and residency IDs are semi-public by design (printed on cards, carried in QR codes), so
   * an unguarded route would let anyone who can read an ID cancel that person's credential.
   * The audit entry names the operator who did it.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('revoker')
  @Post('revoke/:residentId')
  async revoke(@Req() req: RequestWithOperator, @Param('residentId') residentId: string) {
    const operator = requireOperator(req);
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    const cfg = this.platform.getConfig(record.countryCode)!;
    const ok = await this.platform.getResidency().revoke(cfg, residentId);
    await this.platform.syncStatusList(cfg);
    await this.platform.getAudit().record({
      action: 'residency.revoke',
      actor: operatorActor(operator),
      target: residentId,
      countryCode: cfg.countryCode,
      outcome: ok ? 'success' : 'failure',
    });
    return { revoked: ok };
  }

  /**
   * Move a residency relationship to another state: end it, suspend it, reinstate it.
   *
   * This is the act revoking a credential could never express. Revocation says a key is dead;
   * this says the person's relationship to this jurisdiction changed, and records who decided,
   * when, and why. ORCS §10 asks the same four things of revocation and does not get them yet
   * (finding G-07), which is exactly why the two must not share one lever.
   *
   * Deliberately does NOT revoke the credential as a side effect. A jurisdiction ending a
   * residency will usually want to revoke too, but making that automatic would re-collapse the
   * two acts and leave the audit trail unable to say which one was intended -- the conflation
   * ADR-0007 exists to undo. The caller makes both calls, and both are audited.
   *
   * `revoker`-guarded, matching revocation: this is a privileged act on somebody else's
   * identity, and resident ids are semi-public by design.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('revoker')
  @Post(':residentId/relationship/transition')
  async transitionRelationship(
    @Req() req: RequestWithOperator,
    @Param('residentId') residentId: string,
    @Body() body: TransitionRelationshipDto,
  ) {
    const operator = requireOperator(req);
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');

    const result = await this.platform.getResidency().transitionRelationship(residentId, {
      to: body.status,
      by: operatorActor(operator),
      reason: body.reason,
    });

    await this.platform.getAudit().record({
      action: 'residency.relationship.transition',
      actor: operatorActor(operator),
      target: residentId,
      countryCode: record.countryCode,
      outcome: result.ok ? 'success' : 'failure',
    });

    if (!result.ok) throw new BadRequestException(result.reason);
    return {
      residentId,
      from: result.from,
      to: result.to,
      relationship: result.record.relationship,
    };
  }

  /**
   * What this relationship states about itself (ORCS §4.3).
   *
   * Separate from `GET /residency/{residentId}`, which reports registration details that
   * cannot change. This is the one that can.
   */
  @Get(':residentId/relationship')
  async relationship(@Param('residentId') residentId: string) {
    const attrs = await this.platform.getResidency().relationshipFor(residentId);
    if (!attrs) throw new NotFoundException('Unknown residentId');
    return { residentId, relationship: attrs };
  }

  /**
   * Move a credential through its ORCS §10 lifecycle: suspend it, reinstate it, revoke it,
   * or record that it was replaced.
   *
   * This is what `POST /residency/revoke/{residentId}` could not do. That endpoint flipped a
   * bit and returned true; a cleared bit was indistinguishable from one never set, and nothing
   * recorded who decided, why, or where a citizen contests it. §10 requires all four, and the
   * engine refuses a terminal transition that is missing any of them rather than writing a
   * blank into the record.
   *
   * Distinct from `/relationship/transition`: that says whether the person still resides here,
   * this says whether this key still works.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('revoker')
  @Post(':residentId/credential/transition')
  async transitionCredential(
    @Req() req: RequestWithOperator,
    @Param('residentId') residentId: string,
    @Body() body: CredentialTransitionDto,
  ) {
    const operator = requireOperator(req);
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    const cfg = this.platform.getConfig(record.countryCode)!;

    const result = await this.platform.getResidency().transitionCredential(cfg, residentId, {
      to: body.status,
      reason: body.reason,
      // The authority is the authenticated operator, never something the caller asserts.
      authority: operatorActor(operator),
      appealPath: body.appealPath ?? cfg.credential.appealPath,
      supersededBy: body.supersededBy,
    });

    await this.platform.getAudit().record({
      action: 'residency.credential.transition',
      actor: operatorActor(operator),
      target: residentId,
      countryCode: cfg.countryCode,
      outcome: result.ok ? 'success' : 'failure',
    });

    if (!result.ok) throw new BadRequestException(result.reason);
    await this.platform.syncStatusList(cfg);
    return {
      residentId,
      from: result.from,
      to: result.to,
      credentialStatus: result.record.credentialStatus,
    };
  }

  /** The credential's ORCS §10 status: why, by whom, when, and how to appeal. */
  @Get(':residentId/credential')
  async credentialStatus(@Param('residentId') residentId: string) {
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    const cfg = this.platform.getConfig(record.countryCode)!;
    const status = await this.platform.getResidency().credentialStatusFor(cfg, residentId);
    return { residentId, credentialStatus: status };
  }

  /**
   * Erase a resident's personal data, on request or under retention policy.
   *
   * The mechanism DPG Standard indicator 7 and ORCS §14 require. Three things happen, in this
   * order, and the order is the design:
   *
   *   1. The credential is revoked, so what the citizen holds is dead before its subject
   *      becomes unidentifiable. Erasing first would leave a credential that still verifies
   *      against a register no longer able to say whose it is.
   *   2. Every identifying field on the record is destroyed -- names, date of birth, gender,
   *      contact details, and the tokenized reference linking it to a foundational identity.
   *   3. Audit events naming the subject are REDACTED, not deleted. The rows and their hashes
   *      stay, so the tamper-evident chain still verifies; the plaintext goes; and each
   *      redaction is itself appended as a chained event naming who did it and under what
   *      authority. Erasure cannot be performed invisibly.
   *
   * `admin`-guarded rather than `revoker`: this is more destructive than revocation, and a
   * caller who can erase can also destroy the evidence of their own earlier actions --
   * which is exactly why the redaction record exists and why the actor is named in it.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('admin')
  @Post(':residentId/erase')
  async erase(
    @Req() req: RequestWithOperator,
    @Param('residentId') residentId: string,
    @Body() body: { reason?: string; legalBasis?: string },
  ) {
    const operator = requireOperator(req);
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    const cfg = this.platform.getConfig(record.countryCode)!;

    const result = await this.platform.getResidency().erase(cfg, residentId);
    await this.platform.syncStatusList(cfg);

    // Recorded BEFORE redaction, so the erasure itself is in the chain that gets verified.
    await this.platform.getAudit().record({
      action: 'resident.erase',
      actor: operatorActor(operator),
      target: residentId,
      countryCode: cfg.countryCode,
      outcome: result.status === 'unknown' ? 'failure' : 'success',
      metadata: {
        status: result.status,
        reason: body?.reason ?? null,
        legalBasis: body?.legalBasis ?? null,
      },
    });

    const redactedSeqs = await this.platform.getAudit().redactSubject(residentId, {
      actor: operatorActor(operator),
      reason: body?.reason ?? 'erasure request',
      legalBasis: body?.legalBasis,
    });

    const chain = await this.platform.getAudit().verifyChain();
    return {
      status: result.status,
      residentId,
      erasedAt: result.record?.erasedAt,
      auditEventsRedacted: redactedSeqs.length,
      // Returned so the caller can see, in the same response, that erasing did not damage
      // the integrity guarantee. A DPO signing off on a deletion should not have to take
      // that on trust.
      auditChainIntact: chain.ok,
    };
  }

  /**
   * Run the retention sweep: erase every residency record past its retention period.
   *
   * **Dry run unless `confirm: true`.** This is a bulk, irreversible operation on other
   * people's records, and the scope of it should never be something an operator discovers
   * afterwards. A dry run returns exactly which residents would be erased, so the decision is
   * made with the list in hand.
   *
   * `admin`-guarded, like single-record erasure and for the same reason: it destroys data and
   * redacts the audit entries that name it.
   *
   * The sweep refuses to run under a legal hold, and does nothing when no period is set —
   * both reported as `skipped` rather than as an empty success, because "nothing was due" and
   * "the policy is switched off" look identical otherwise, and an operator who believes a
   * sweep ran when it was held is badly misled.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('admin')
  @Post('retention/sweep')
  async retentionSweep(
    @Req() req: RequestWithOperator,
    @Body() body: { countryCode?: string; confirm?: boolean; reason?: string },
  ) {
    const operator = requireOperator(req);
    const configs = body?.countryCode
      ? [this.platform.getConfig(body.countryCode)].filter(Boolean)
      : this.platform.listConfigs();
    if (!configs.length) throw new NotFoundException('No matching country config');

    const confirmed = body?.confirm === true;
    const report: Array<Record<string, unknown>> = [];

    for (const cfg of configs as NonNullable<(typeof configs)[number]>[]) {
      const selection = await this.platform.getResidency().selectDueForRetention(cfg);
      const due = selection.due.map((r) => r.residentId);

      if (!confirmed || selection.skipped) {
        report.push({
          countryCode: cfg.countryCode,
          dueCount: due.length,
          due,
          skipped: selection.skipped,
          erased: 0,
        });
        continue;
      }

      let erased = 0;
      for (const residentId of due) {
        const result = await this.platform.getResidency().erase(cfg, residentId);
        if (result.status !== 'erased') continue;
        erased++;
        await this.platform.getAudit().record({
          action: 'resident.erase',
          actor: operatorActor(operator),
          target: residentId,
          countryCode: cfg.countryCode,
          outcome: 'success',
          metadata: { via: 'retention-sweep', reason: body?.reason ?? 'retention period elapsed' },
        });
        await this.platform.getAudit().redactSubject(residentId, {
          actor: operatorActor(operator),
          reason: body?.reason ?? 'retention period elapsed',
        });
      }
      await this.platform.syncStatusList(cfg);
      report.push({ countryCode: cfg.countryCode, dueCount: due.length, due, erased });
    }

    // The sweep itself is audited whether or not it erased anything. "A sweep ran and found
    // nothing due" is a fact a controller needs to be able to evidence.
    await this.platform.getAudit().record({
      action: 'admin.read',
      actor: operatorActor(operator),
      outcome: 'success',
      metadata: {
        view: 'retention-sweep',
        dryRun: !confirmed,
        countries: report.map((r) => r.countryCode),
        totalErased: report.reduce((n, r) => n + (r.erased as number), 0),
      },
    });

    const chain = await this.platform.getAudit().verifyChain();
    return { dryRun: !confirmed, results: report, auditChainIntact: chain.ok };
  }

  /** Verify a presented residency credential (server-side; verifiers can also do this offline). */
  @Post('verify')
  async verify(@Body() body: VerifyDto) {
    // Make sure the verifier has the latest revocation snapshot for all configs.
    for (const cfg of this.platform.listConfigs()) {
      await this.platform.syncStatusList(cfg);
    }
    const outcome = await this.platform
      .getVerifier()
      .verify(body.credential, { offline: body.offline ?? false });
    await this.platform.getAudit().record({
      action: 'credential.verify',
      actor: 'verifier',
      target:
        typeof outcome.subject?.residentId === 'string'
          ? (outcome.subject.residentId as string)
          : undefined,
      outcome: outcome.valid ? 'success' : 'failure',
      metadata: { reason: outcome.valid ? undefined : outcome.reason },
    });
    return outcome;
  }
}
