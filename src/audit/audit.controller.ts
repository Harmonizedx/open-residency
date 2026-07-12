import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { AdminKeyGuard } from '../common/api-key.guard';

/**
 * Audit read API. Privileged: guarded by the admin key. The log itself is written
 * by the services (issue, revoke, verify, consent) as they act; this controller only
 * exposes it for oversight and lets an auditor verify the hash chain is intact.
 */
@Controller('audit')
@UseGuards(AdminKeyGuard)
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

  @Get('verify')
  async verify() {
    return this.platform.getAudit().verifyChain();
  }
}
