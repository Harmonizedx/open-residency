// SPDX-License-Identifier: Apache-2.0
import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { OperatorGuard, RequireRoles, RequestWithOperator, requireOperator } from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
import { PlatformService } from '../platform/platform.service';
import { ArrivalNotice } from '../core/residency/arrival-notice';
import {
  ListArrivalNoticesQueryDto,
  ReceiveArrivalNoticeDto,
  ResolveArrivalNoticeDto,
  SendArrivalNoticeDto,
} from './dto/federation.dto';

/**
 * Arrival notices between federated jurisdictions (ADR-0018).
 *
 * One public route, for peers: a signed notice is its own credential, and the signature is
 * checked against the trust list before anything else happens. Everything else is an
 * operator's: telling a peer about a mover, reading what peers have said, and deciding a
 * conflict. No route here reads or writes another jurisdiction's register.
 */
@Controller('federation')
export class FederationController {
  constructor(private platform: PlatformService) {}

  /**
   * A peer reports that a person holding one of this deployment's credentials registered
   * with it. Accepted only from a peer in the trust list, signed by a key the list holds,
   * addressed to this deployment, within validity, and never seen before. What happens next
   * is this deployment's declared rule for that peer; the response says which rule and what
   * it did, and no more. Rate-limited like every public route.
   */
  @Post('arrival-notices')
  async receive(@Body() body: ReceiveArrivalNoticeDto) {
    const result = await this.platform.getArrivalNotices().receive(body.notice);
    await this.platform.getAudit().record({
      action: 'federation.arrival-notice.receive',
      actor: result.ok ? `peer:${result.notice.peerDid}` : 'peer:unverified',
      target: result.ok ? result.notice.residentId : undefined,
      countryCode: result.ok ? result.notice.countryCode : undefined,
      outcome: result.ok ? 'success' : 'failure',
      metadata: result.ok
        ? {
            noticeId: result.notice.id,
            status: result.notice.status,
            rule: result.notice.rule,
            conflict: result.notice.conflict,
            appliedTransition: result.notice.appliedTransition,
          }
        : { reason: result.reason },
    });
    if (!result.ok) {
      if (result.kind === 'replay') throw new ConflictException(result.reason);
      if (result.kind === 'untrusted') throw new UnauthorizedException(result.reason);
      throw new BadRequestException(result.reason);
    }
    const n = result.notice;
    return {
      id: n.id,
      status: n.status,
      conflict: n.conflict,
      rule: n.rule,
      graceDays: n.graceDays,
      effectiveAt: n.effectiveAt,
      appliedTransition: n.appliedTransition,
    };
  }

  /**
   * A person presented a peer's credential here and was registered here: tell the peer.
   * The credential is verified through the federation trust list first, so this deployment
   * never vouches to a peer for a credential it would not itself accept.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('arrival-notices/outbound')
  async send(@Req() req: RequestWithOperator, @Body() body: SendArrivalNoticeDto) {
    const operator = requireOperator(req);
    const result = await this.platform.getArrivalNotices().notify({
      countryCode: body.countryCode.toUpperCase(),
      credential: body.credential,
      presentedAt: body.presentedAt,
      registeredAt: body.registeredAt,
    });
    await this.platform.getAudit().record({
      action: 'federation.arrival-notice.send',
      actor: operatorActor(operator),
      countryCode: body.countryCode.toUpperCase(),
      outcome: result.ok ? 'success' : 'failure',
      metadata: result.ok
        ? { noticeId: result.notice.id, peerDid: result.notice.peerDid, status: result.notice.status }
        : { reason: result.reason },
    });
    if (!result.ok) throw new BadRequestException(result.reason);
    return this.view(result.notice);
  }

  /** Notices in either direction, oldest first, filtered by direction, status, resident or country. */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Get('arrival-notices')
  async list(@Query() query: ListArrivalNoticesQueryDto) {
    const page = await this.platform.getArrivalNotices().list({
      direction: query.direction,
      status: query.status,
      residentId: query.residentId,
      countryCode: query.countryCode?.toUpperCase(),
      limit: query.limit,
      offset: query.offset,
    });
    return { total: page.total, items: page.items.map((n) => this.view(n)) };
  }

  /**
   * Apply every inbound notice whose grace period has run, and retry outbound notices whose
   * delivery failed. The background job does the same on its interval; this is for a
   * deployment that drives it by hand, and for tests.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('arrival-notices/sweep')
  async sweep() {
    return this.platform.sweepArrivalNotices();
  }

  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Get('arrival-notices/:id')
  async get(@Param('id') id: string) {
    const notice = await this.platform.getArrivalNotices().get(id);
    if (!notice) throw new NotFoundException('Unknown notice');
    return this.view(notice);
  }

  /**
   * A person decides a conflict. `revoker`-guarded because reversing a suspension reinstates
   * a relationship and upholding a pending notice ends or suspends one: the same privilege
   * as the relationship transition route.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('revoker')
  @Post('arrival-notices/:id/resolve')
  async resolve(@Req() req: RequestWithOperator, @Param('id') id: string, @Body() body: ResolveArrivalNoticeDto) {
    const operator = requireOperator(req);
    const existing = await this.platform.getArrivalNotices().get(id);
    if (!existing) throw new NotFoundException('Unknown notice');
    const result = await this.platform.getArrivalNotices().resolve(id, {
      by: operatorActor(operator),
      resolution: body.resolution,
      reason: body.reason,
    });
    await this.platform.getAudit().record({
      action: 'federation.arrival-notice.resolve',
      actor: operatorActor(operator),
      target: existing.residentId,
      countryCode: existing.countryCode,
      outcome: result.ok ? 'success' : 'failure',
      metadata: result.ok
        ? { noticeId: id, resolution: body.resolution, appliedTransition: result.notice.appliedTransition }
        : { noticeId: id, resolution: body.resolution, reason: result.reason },
    });
    if (!result.ok) throw new BadRequestException(result.reason);
    return this.view(result.notice);
  }

  /** The notice as an operator sees it: everything stored, including the signed notice itself. */
  private view(n: ArrivalNotice) {
    return { ...n };
  }
}
