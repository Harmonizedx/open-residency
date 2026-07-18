import {
  Body,
  Controller,
  Get,
  Inject,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import type Provider from 'oidc-provider';
import { OperatorGuard, RequireRoles } from '../common/operator.guard';
import { PlatformService } from '../platform/platform.service';

/**
 * Consent API for the citizen-facing side.
 *
 * Grants are normally created during the SSO consent step, but they are first-class
 * revocable records here: a citizen can see everything they have shared and withdraw it.
 *
 * These were previously unauthenticated, on the reasoning that they are citizen-facing.
 * That does not hold: with no caller identity, "citizen-facing" means anyone can read any
 * resident's entire sharing history from their (semi-public) residency ID, revoke someone
 * else's consent, or write a forged grant record. Nothing legitimate depended on the open
 * routes -- the SSO consent step calls ConsentService directly rather than over HTTP, so
 * the only HTTP caller was the admin console.
 *
 * Admin-guarding is the conservative interim: it closes the hole without inventing a
 * citizen auth model. The intended end state is still per-citizen authentication (the same
 * OIDC login), at which point a resident should reach only their OWN records and this
 * guard becomes the operator-facing path.
 */
@UseGuards(OperatorGuard)
@RequireRoles('support')
@Controller('consent')
export class ConsentController {
  constructor(
    private platform: PlatformService,
    @Inject('OIDC_PROVIDER') private provider: Provider,
  ) {}

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

    // Withdrawing consent has to stop the claim release, not just record that it was
    // withdrawn. The consent record and the OIDC grant were previously independent, so a
    // revoked consent left the grant live and the relying party kept reading residency
    // claims for the life of its tokens -- up to the refresh-token TTL. Destroy the grant
    // and revoke everything issued under it.
    let sessionRevoked = false;
    if (updated.grantId) {
      const grant = await this.provider.Grant.find(updated.grantId);
      if (grant) await grant.destroy();
      await Promise.all([
        this.provider.AccessToken.revokeByGrantId(updated.grantId),
        this.provider.RefreshToken.revokeByGrantId(updated.grantId),
        this.provider.AuthorizationCode.revokeByGrantId(updated.grantId),
      ]);
      sessionRevoked = true;
    }

    await this.platform.getAudit().record({
      action: 'consent.revoke',
      actor: updated.residentId,
      target: updated.relyingParty,
      outcome: 'success',
      metadata: { consentId: id, sessionRevoked },
    });
    return { consent: updated, sessionRevoked };
  }
}
