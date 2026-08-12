// SPDX-License-Identifier: Apache-2.0
import { Controller, Get, Header, Req, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import {
  OperatorGuard,
  RequireRoles,
  RequestWithOperator,
  requireOperator,
} from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
import {
  aggregateResidency,
  project,
  toCsv,
  StatisticsInput,
} from '../core/statistics/aggregate';

/** How many records to pull per page while walking the register. */
const PAGE_SIZE = 500;

/**
 * The non-PII data extraction surface (DPG Standard indicator 6).
 *
 * Returns aggregate residency counts in JSON and RFC 4180 CSV -- non-proprietary formats
 * a deployer can publish as open data or load into any analysis tool. Resident-level data
 * is deliberately not here: `/admin/residents` serves that, it is personal data, and it is
 * governed as such.
 *
 * Small-cell suppression is applied even though the caller is an authenticated operator
 * who could read the register directly. The suppression is a property of the artifact, not
 * of the audience -- this output is shaped to be publishable, and shipping an operator an
 * unsuppressed file they then publish is exactly the failure mode it prevents.
 */
@Controller('admin')
@UseGuards(OperatorGuard)
@RequireRoles('support')
export class StatisticsController {
  constructor(private platform: PlatformService) {}

  /**
   * Deployer policy, not a caller parameter. If the threshold were a query argument,
   * `?threshold=1` would turn the disclosure control off from the outside.
   */
  private threshold(): number {
    const raw = Number(process.env.STATISTICS_SUPPRESSION_THRESHOLD);
    return Number.isFinite(raw) && raw >= 0 ? raw : 5;
  }

  /** Walk the whole register, keeping only the non-PII projection of each record. */
  private async collect(): Promise<StatisticsInput[]> {
    const store = this.platform.getStore();
    const rows: StatisticsInput[] = [];
    let offset = 0;
    for (;;) {
      const page = await store.list({ limit: PAGE_SIZE, offset });
      for (const record of page.items) rows.push(project(record));
      offset += page.items.length;
      if (page.items.length === 0 || offset >= page.total) break;
    }
    return rows;
  }

  private async report(req: RequestWithOperator, format: 'json' | 'csv') {
    const residents = await this.collect();
    const stats = aggregateResidency(residents, { suppressionThreshold: this.threshold() });
    await this.platform.getAudit().record({
      action: 'admin.read',
      actor: operatorActor(requireOperator(req)),
      outcome: 'success',
      metadata: { view: 'statistics', format },
    });
    return stats;
  }

  @Get('statistics')
  async statisticsJson(@Req() req: RequestWithOperator) {
    return this.report(req, 'json');
  }

  @Get('statistics.csv')
  @Header('content-type', 'text/csv; charset=utf-8')
  @Header('content-disposition', 'attachment; filename="openresidency-statistics.csv"')
  async statisticsCsv(@Req() req: RequestWithOperator): Promise<string> {
    return toCsv(await this.report(req, 'csv'));
  }
}
