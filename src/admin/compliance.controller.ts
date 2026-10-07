// SPDX-License-Identifier: Apache-2.0
import { BadRequestException, Body, Controller, Get, Post, Query, Req, UseGuards } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { PlatformService } from '../platform/platform.service';
import { OperatorGuard, RequireRoles, RequestWithOperator, requireOperator } from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
import { dpiaFacts, recordOfProcessing } from '../core/privacy/compliance';
import { buildBreachRecord } from '../core/privacy/breach';
import { RecordBreachDto } from './dto/breach.dto';

/**
 * What the data-protection officer needs from the system, produced by the system.
 *
 * The record of processing and the impact-assessment facts are generated from the live
 * configuration and labelled as skeletons, not filings: every field the software cannot know
 * is listed for the deployment to complete. The breach register is append-only and holds no
 * subject identifiers. All of it is for the admin role, because these documents describe the
 * whole deployment.
 */
@Controller('admin/compliance')
@UseGuards(OperatorGuard)
@RequireRoles('admin')
export class ComplianceController {
  constructor(private platform: PlatformService) {}

  private cfgFor(countryCode?: string) {
    const cfg = countryCode ? this.platform.getConfig(countryCode) : this.platform.listConfigs()[0];
    if (!cfg) throw new BadRequestException('Unknown countryCode');
    return cfg;
  }

  /** The record of processing activities, as far as the configuration can state it. */
  @Get('ropa')
  async ropa(@Req() req: RequestWithOperator, @Query('countryCode') countryCode?: string) {
    const cfg = this.cfgFor(countryCode);
    const out = recordOfProcessing(cfg, this.platform.getRegulatoryProfile(cfg.countryCode));
    await this.platform.getAudit().record({
      action: 'admin.compliance.read',
      actor: operatorActor(requireOperator(req)),
      countryCode: cfg.countryCode,
      outcome: 'success',
      metadata: { document: 'ropa' },
    });
    return out;
  }

  /** The facts an impact assessment starts from, and which triggers apply to this deployment. */
  @Get('dpia')
  async dpia(@Req() req: RequestWithOperator, @Query('countryCode') countryCode?: string) {
    const cfg = this.cfgFor(countryCode);
    const out = dpiaFacts(cfg, this.platform.getRegulatoryProfile(cfg.countryCode));
    await this.platform.getAudit().record({
      action: 'admin.compliance.read',
      actor: operatorActor(requireOperator(req)),
      countryCode: cfg.countryCode,
      outcome: 'success',
      metadata: { document: 'dpia' },
    });
    return out;
  }

  /** The breach register, oldest first. */
  @Get('breaches')
  async breaches(@Query('countryCode') countryCode?: string) {
    return { breaches: await this.platform.getBreaches().list(countryCode) };
  }

  /** Enter a breach. The 72-hour clock runs from `detectedAt`, not from now. */
  @Post('breaches')
  async recordBreach(@Req() req: RequestWithOperator, @Body() body: RecordBreachDto) {
    const operator = requireOperator(req);
    const cfg = this.cfgFor(body.countryCode);
    const record = buildBreachRecord(
      {
        countryCode: cfg.countryCode,
        detectedAt: body.detectedAt,
        recordedBy: operatorActor(operator),
        categories: body.categories,
        description: body.description,
        subjectsAffected: body.subjectsAffected,
        highRisk: body.highRisk,
        containment: body.containment,
        authorityNotifiedAt: body.authorityNotifiedAt,
        subjectsNotifiedAt: body.subjectsNotifiedAt,
        amends: body.amends,
      },
      randomUUID(),
      new Date().toISOString(),
      this.platform.getRegulatoryProfile(cfg.countryCode).breachNotificationHours,
    );
    await this.platform.getBreaches().append(record);
    await this.platform.getAudit().record({
      action: 'privacy.breach.record',
      actor: operatorActor(operator),
      target: record.id,
      countryCode: cfg.countryCode,
      outcome: 'success',
      metadata: { categories: record.categories, highRisk: record.highRisk, amends: record.amends },
    });
    return record;
  }
}
