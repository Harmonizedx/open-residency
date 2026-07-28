import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import {
  OperatorGuard,
  RequireRoles,
  RequestWithOperator,
  requireOperator,
} from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
import { ListResidentsQueryDto } from './dto/list-residents.dto';

/**
 * Administrative view over the Resident Registry.
 *
 * Requires the `support` role. Returns only non-sensitive registry fields (never raw
 * national IDs, which are not stored at all). Reads are audited against the operator who
 * made them: who looked at the register is itself something an auditor asks about.
 */
@Controller('admin')
@UseGuards(OperatorGuard)
@RequireRoles('support')
export class AdminController {
  constructor(private platform: PlatformService) {}

  @Get('residents')
  async residents(@Req() req: RequestWithOperator, @Query() query: ListResidentsQueryDto) {
    const page = await this.platform.getStore().list({
      countryCode: query.countryCode ? query.countryCode.toUpperCase() : undefined,
      limit: query.limit,
      offset: query.offset,
    });
    await this.platform.getAudit().record({
      action: 'admin.read',
      actor: operatorActor(requireOperator(req)),
      outcome: 'success',
      metadata: { view: 'residents', countryCode: query.countryCode },
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
