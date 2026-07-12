import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { AdminKeyGuard } from '../common/api-key.guard';

/**
 * Administrative view over the Resident Registry. Guarded by the admin key.
 * Returns only non-sensitive registry fields (never raw national IDs, which are
 * not stored at all).
 */
@Controller('admin')
@UseGuards(AdminKeyGuard)
export class AdminController {
  constructor(private platform: PlatformService) {}

  @Get('residents')
  async residents(
    @Query('countryCode') countryCode?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ) {
    const page = await this.platform.getStore().list({
      countryCode: countryCode ? countryCode.toUpperCase() : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });
    await this.platform.getAudit().record({
      action: 'admin.read',
      actor: 'admin',
      outcome: 'success',
      metadata: { view: 'residents', countryCode },
    });
    return {
      total: page.total,
      residents: page.items.map((r) => ({
        residentId: r.residentId,
        countryCode: r.countryCode,
        subnationalUnit: r.subnationalUnit,
        providerCode: r.providerCode,
        assuranceLevel: r.assuranceLevel,
        provisional: r.provisional,
        createdAt: r.createdAt,
      })),
    };
  }

  @Get('stats')
  async stats() {
    const configs = this.platform.listConfigs();
    const perCountry: Record<string, number> = {};
    for (const cfg of configs) {
      const page = await this.platform.getStore().list({ countryCode: cfg.countryCode, limit: 1 });
      perCountry[cfg.countryCode] = page.total;
    }
    return { countries: configs.length, residentsByCountry: perCountry };
  }
}
