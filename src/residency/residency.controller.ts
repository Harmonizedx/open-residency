import { Body, Controller, Get, NotFoundException, Param, Post, Req, UseGuards } from '@nestjs/common';
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
import { ApplicantBinding } from '../core/proofing/binding';
import { ResidenceEvidence } from '../core/proofing/residence';
import { residentIdPattern } from '../core/residency/resident-id';

interface IssueBody {
  countryCode: string;
  subnationalUnit: string;
  identifiers: Record<string, string>;
  holderId?: string;
  challengeRef?: string;
  proofOfResidence?: string;
  /**
   * Applicant->identity binding performed by the enrolment channel (an agent's in-person
   * comparison, a face/fingerprint match). Only meaningful from a trusted enrolment
   * context: for the attended/biometric methods this endpoint must sit behind operator
   * authentication, so a citizen cannot self-assert that they were bound. The strongest
   * of this and any provider-attested binding is what the engine enforces and records.
   */
  binding?: ApplicantBinding;
  /**
   * Proof-of-residence evidence gathered by the enrolment channel -- a ward operator's
   * attestation, a sighted utility bill, a geospatial match.
   *
   * Carries the same trust requirement as `binding`: only meaningful from an authenticated
   * operator context, since a citizen who could post their own `authority_attestation`
   * would be attesting their own residence. Evidence the foundational source supplies is
   * collected separately by the engine and capped at RAL1; anything above that has to
   * arrive here, which is why a jurisdiction configured for RAL2 cannot issue without it.
   */
  residenceEvidence?: ResidenceEvidence[];
  /**
   * The applicant's phone in E.164, captured at the desk.
   *
   * Optional, and what happens to it is governed by `contactDirectory.mode`: under
   * `encrypted` it is stored as ciphertext for OTP delivery plus a hash for matching;
   * under `external` or `none` only the hash is kept, because the number either lives in
   * the ministry's own directory or is not wanted here at all. It is never written to the
   * credential, the audit log, or any response.
   */
  phone?: string;
  offline?: boolean;
}

interface VerifyBody {
  credential: string; // VC-JWT
  offline?: boolean;
}

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
  async issue(@Req() req: RequestWithOperator, @Body() body: IssueBody) {
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

  /** Verify a presented residency credential (server-side; verifiers can also do this offline). */
  @Post('verify')
  async verify(@Body() body: VerifyBody) {
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
