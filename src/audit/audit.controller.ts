// SPDX-License-Identifier: Apache-2.0
import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { OperatorGuard, RequireRoles } from '../common/operator.guard';

/**
 * Audit read API. Privileged: guarded by the admin key. The log itself is written
 * by the services (issue, revoke, verify, consent) as they act; this controller only
 * exposes it for oversight and lets an auditor verify the hash chain is intact.
 */
@Controller('audit')
@UseGuards(OperatorGuard)
@RequireRoles('auditor')
export class AuditController {
  constructor(private platform: PlatformService) {}

  @Get()
  async list(
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
    @Query('target') target?: string,
  ) {
    const events = await this.platform.getAudit().list({
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
      target,
    });
    return { count: events.length, events };
  }

  /**
   * Verify the chain, and the anchor that binds its tail.
   *
   * The deployment's own public keys are passed in so the signed checkpoint is actually
   * CHECKED rather than taken on trust. Without them the result reports `anchored: false`,
   * which is the honest answer: an unverified anchor proves nothing, and returning a green
   * tick that covers only the links would tell an auditor the tail was protected when the
   * one attack the links cannot see is the tail being cut.
   *
   * Retired keys are included, because a log outlives the key that anchored it and a
   * rotation must not retrospectively invalidate every checkpoint signed before it.
   */
  @Get('verify')
  async verify() {
    return this.platform
      .getAudit()
      .verifyChain({ publicJwks: this.platform.issuerPublicJwks() });
  }
}
