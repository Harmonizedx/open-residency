// SPDX-License-Identifier: Apache-2.0
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Inject,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import type Provider from 'oidc-provider' with { 'resolution-mode': 'import' };
import { OperatorGuard, RequireRoles } from '../common/operator.guard';
import { PlatformService } from '../platform/platform.service';
import { DeactivateLegalBasisDto, GrantConsentDto } from './dto/grant-consent.dto';

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
  async grant(@Body() body: GrantConsentDto) {
    const resident = await this.platform.getStore().findByResidentId(body.residentId);
    if (!resident) throw new NotFoundException('Unknown residentId');
    const outcome = await this.platform.getConsent().grant({
      residentId: body.residentId,
      subjectRef: body.subjectRef ?? resident.subjectRef,
      relyingParty: body.relyingParty,
      relyingPartyName: body.relyingPartyName,
      purpose: body.purpose,
      scopes: body.scopes,
      validityDays: body.validityDays,
      dataCategories: body.dataCategories,
      legalBasisReference: body.legalBasisReference,
      evidence: {
        method: body.evidenceMethod as 'operator_recorded',
        at: body.evidenceAt ?? new Date().toISOString(),
        reference: body.evidenceReference,
        capturedBy: body.evidenceCapturedBy,
      },
    });

    // A refused grant is audited too. A register that logs only the consents it accepted
    // cannot answer "was this person's permission ever sought", which is the question a
    // complaint starts with.
    await this.platform.getAudit().record({
      action: 'consent.grant',
      actor: body.residentId,
      target: body.relyingParty,
      outcome: outcome.ok ? 'success' : 'failure',
      metadata: outcome.ok
        ? { scopes: body.scopes, purpose: body.purpose, consentId: outcome.record.id }
        : { scopes: body.scopes, purpose: body.purpose, reason: outcome.reason },
    });
    if (!outcome.ok) throw new BadRequestException(outcome.reason);
    return { consent: outcome.record, receipt: outcome.receipt };
  }

  // ---- Legal Basis Registry (ORCS §9) --------------------------------------

  @Get('legal-bases')
  listLegalBases() {
    return { legalBases: this.platform.getLegalBases().list() };
  }

  /**
   * A single basis, whatever its state.
   *
   * Deliberately served from `get` rather than `resolve`: a consent granted under a
   * since-withdrawn by-law cites this id, and an auditor following that citation needs the
   * record. `inForce` is reported separately so a caller cannot mistake "it exists" for "it
   * still authorises processing".
   */
  @Get('legal-bases/:id')
  getLegalBasis(@Param('id') id: string) {
    const basis = this.platform.getLegalBases().get(id);
    if (!basis) throw new NotFoundException('Unknown legal basis');
    return { legalBasis: basis, inForce: this.platform.getLegalBases().resolve(id) !== null };
  }

  @Post('legal-bases/:id/deactivate')
  @RequireRoles('admin')
  async deactivateLegalBasis(@Param('id') id: string, @Body() body: DeactivateLegalBasisDto) {
    const outcome = this.platform.getLegalBases().deactivate(id, {
      reason: body.reason,
      authority: body.authority,
    });
    await this.platform.getAudit().record({
      action: 'legalBasis.deactivate',
      actor: body.authority,
      target: id,
      outcome: outcome.ok ? 'success' : 'failure',
      metadata: outcome.ok ? { reason: body.reason } : { reason: outcome.reason },
    });
    if (!outcome.ok) {
      if (outcome.reason === 'UNKNOWN_LEGAL_BASIS') throw new NotFoundException(outcome.reason);
      throw new BadRequestException(outcome.reason);
    }
    return { legalBasis: outcome.basis };
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
