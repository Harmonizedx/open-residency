// SPDX-License-Identifier: Apache-2.0
import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Post,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import * as QRCode from 'qrcode';
import { PlatformService } from '../platform/platform.service';
import { accessLogFor } from '../core/audit/access-log';
import { AccessLogDto, AccessLogStartDto } from './dto/me.dto';

/**
 * What a resident can see about their own record, without a staff account.
 *
 * ## Who pays for proving who you are
 *
 * The register already has three ways a resident proves control of their record, and they
 * differ in who pays. A one-time code is an SMS the agency pays for, every time, on behalf of
 * every resident who is curious. Presenting the credential from a wallet costs nothing: the
 * phone signs a challenge with the key the credential is bound to. A USSD session costs the
 * agency nothing per use either: the network attributes the session to the SIM, and the
 * register already holds the hash of the registered number. So the free factors come first,
 * the paid one is a fallback, and a deployment that will not pay for messages removes it from
 * `selfService.accessLogFactors` and loses nothing.
 *
 * ## Enumeration
 *
 * Every path keeps the discipline the sign-in flow keeps. `start` answers identically whether
 * the record exists or not; a failed code is one generic 401; the presentation flow's request
 * id is a server-minted capability that says nothing about any resident until a wallet has
 * proved possession. A surface that let anyone learn whether a residency id is real would be a
 * harm of its own, and a resident's access log is not worth that.
 */
@Controller('me')
export class MeController {
  constructor(private platform: PlatformService) {}

  private factors(): ReadonlyArray<'presentation' | 'ussd' | 'otp'> {
    return this.platform.listConfigs()[0]?.selfService.accessLogFactors ?? ['presentation', 'ussd', 'otp'];
  }

  private requireFactor(f: 'presentation' | 'ussd' | 'otp'): void {
    if (!this.factors().includes(f)) {
      throw new ForbiddenException(`self-service factor '${f}' is not enabled on this deployment`);
    }
  }

  /** The factors this deployment accepts, so a client renders only the paths that will work. */
  @Get('access-log/factors')
  factorsAvailable() {
    return { factors: this.factors() };
  }

  // ---- Free factor: present the credential ----------------------------------------------

  /**
   * Begin a presentation. Returns the OpenID4VP request URI and a QR of it for the resident's
   * wallet to scan; the wallet posts its presentation out of band, exactly as for sign-in.
   */
  @Post('access-log/presentation/start')
  async presentationStart() {
    this.requireFactor('presentation');
    const { requestId, requestUri } = await this.platform.getSsoAuth().beginVpLogin();
    const qrSvg = await QRCode.toString(requestUri, { type: 'svg', margin: 1 });
    return { requestId, requestUri, qrSvg };
  }

  /**
   * Collect the access log once the wallet has presented. Before that, reports the status and
   * nothing else. The request id is the capability; it was minted here and handed to the
   * resident's own browser, and it expires with the presentation request.
   */
  @Get('access-log/presentation')
  async presentationResult(@Query('requestId') requestId?: string) {
    this.requireFactor('presentation');
    // Always ask the service; an absent or unknown id comes back as a non-authenticated status.
    // No user-supplied value decides whether the check runs -- only the service's answer
    // decides what is returned.
    const result = await this.platform.getSsoAuth().pollVpLogin(String(requestId ?? ''));
    if (result.status !== 'authenticated' || !result.residentId) return { status: result.status };
    return { status: 'authenticated', ...(await this.entriesFor(result.residentId)) };
  }

  // ---- Paid fallback: a one-time code ---------------------------------------------------

  /** Send a one-time code to the record's registered contact. Answers the same either way. */
  @Post('access-log/start')
  async start(@Body() body: AccessLogStartDto) {
    this.requireFactor('otp');
    if (body?.residentId) {
      try {
        await this.platform.getSsoAuth().beginOtpLogin(body.residentId);
      } catch (e) {
        await this.platform.getAudit().record({
          action: 'sso.login',
          actor: body.residentId,
          outcome: 'failure',
          metadata: { factor: 'otp', stage: 'delivery', purpose: 'access-log', reason: (e as Error).message },
        });
      }
    }
    return { sent: true };
  }

  /** Who has looked at my record, proved by the code that was sent. */
  @Post('access-log')
  async accessLog(@Body() body: AccessLogDto) {
    this.requireFactor('otp');
    // The verification always runs, with whatever was supplied: a missing id or code is just a
    // code that does not verify. The service's answer, not a user-supplied value, is the only
    // thing that decides whether the log is returned.
    const result = await this.platform
      .getSsoAuth()
      .verifyOtpLogin(String(body.residentId ?? ''), String(body.code ?? ''));
    if (!result.authenticated || !result.residentId) {
      await this.platform.getAudit().record({
        action: 'sso.login',
        actor: 'resident',
        outcome: 'failure',
        metadata: { factor: 'otp', purpose: 'access-log', reason: result.reason ?? 'NOT_VERIFIED' },
      });
      throw new UnauthorizedException('Incorrect or expired code');
    }
    return this.entriesFor(result.residentId);
  }

  /**
   * The entries, with the read itself recorded: reading one's access log is an access, and
   * the trail stays complete. Shared by every factor; the USSD path uses the same function
   * through the offline controller.
   */
  private async entriesFor(residentId: string) {
    const audit = this.platform.getAudit();
    const entries = await accessLogFor(audit, residentId);
    await audit.record({
      action: 'resident.access.read',
      actor: residentId,
      target: residentId,
      outcome: 'success',
      metadata: { entries: entries.length, factor: 'self-service' },
    });
    return { residentId, entries };
  }
}
