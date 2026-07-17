import { Body, Controller, Get, NotFoundException, Param, Post } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { ApplicantBinding } from '../core/proofing/binding';
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

  @Post('issue')
  async issue(@Body() body: IssueBody) {
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
      context: { offline: body.offline === true },
    });
    await this.platform.getAudit().record({
      action: 'residency.issue',
      actor: 'citizen',
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

  @Post('revoke/:residentId')
  async revoke(@Param('residentId') residentId: string) {
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');
    const cfg = this.platform.getConfig(record.countryCode)!;
    const ok = await this.platform.getResidency().revoke(cfg, residentId);
    await this.platform.syncStatusList(cfg);
    await this.platform.getAudit().record({
      action: 'residency.revoke',
      actor: 'admin',
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
