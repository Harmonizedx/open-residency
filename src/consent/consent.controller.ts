import { Body, Controller, Get, NotFoundException, Param, Post } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';

/**
 * Consent API for the citizen-facing side.
 *
 * Grants are normally created during the SSO consent step, but they are first-class
 * revocable records here: a citizen can see everything they have shared and withdraw
 * it. In a hardened deployment these routes sit behind citizen authentication (the
 * same OIDC login); left open here for the reference build, and every action is
 * audited.
 */
@Controller('consent')
export class ConsentController {
  constructor(private platform: PlatformService) {}

  @Get('resident/:residentId')
  async listForResident(@Param('residentId') residentId: string) {
    const records = await this.platform.getConsent().listByResident(residentId);
    return { residentId, consents: records };
  }

  @Post('grant')
  async grant(
    @Body()
    body: {
      residentId: string;
      subjectRef?: string;
      relyingParty: string;
      relyingPartyName?: string;
      purpose: string;
      scopes: string[];
      validityDays?: number;
    },
  ) {
    const resident = await this.platform.getStore().findByResidentId(body.residentId);
    if (!resident) throw new NotFoundException('Unknown residentId');
    const { record, receipt } = await this.platform.getConsent().grant({
      residentId: body.residentId,
      subjectRef: body.subjectRef ?? resident.subjectRef,
      relyingParty: body.relyingParty,
      relyingPartyName: body.relyingPartyName,
      purpose: body.purpose,
      scopes: body.scopes,
      validityDays: body.validityDays,
    });
    await this.platform.getAudit().record({
      action: 'consent.grant',
      actor: body.residentId,
      target: body.relyingParty,
      outcome: 'success',
      metadata: { scopes: body.scopes, purpose: body.purpose },
    });
    return { consent: record, receipt };
  }

  @Post(':id/revoke')
  async revoke(@Param('id') id: string) {
    const updated = await this.platform.getConsent().revoke(id);
    if (!updated) throw new NotFoundException('Unknown consent id');
    await this.platform.getAudit().record({
      action: 'consent.revoke',
      actor: updated.residentId,
      target: updated.relyingParty,
      outcome: 'success',
      metadata: { consentId: id },
    });
    return { consent: updated };
  }
}
