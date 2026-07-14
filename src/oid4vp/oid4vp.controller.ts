import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { AdminKeyGuard } from '../common/api-key.guard';
import { Oid4vpError } from '../core/oid4vp/oid4vp-service';

function toHttp(e: unknown): never {
  if (e instanceof Oid4vpError) {
    throw new HttpException({ error: e.code, error_description: e.message }, e.status);
  }
  throw e;
}

/**
 * OpenID4VP: the endpoints a relying party and a wallet use to complete a presentation.
 *
 * Note which of these are guarded and which are not. Creating a request and reading its
 * result are relying-party actions and require the API key -- being able to read outcomes
 * means being able to read residency claims. Fetching the request object and posting the
 * response are wallet actions on an unauthenticated device, and are protected instead by
 * the request being unguessable, short-lived, and single-use.
 */
@Controller('openid4vp')
export class Oid4vpController {
  constructor(private platform: PlatformService) {}

  /** A relying party opens a presentation request. Returns a QR-able openid4vp:// URI. */
  @Post('request')
  @UseGuards(AdminKeyGuard)
  async createRequest(@Body() body: { purpose?: string; reference?: string }) {
    try {
      return await this.platform.getOid4vp().createRequest(body ?? {});
    } catch (e) {
      toHttp(e);
    }
  }

  /** The wallet dereferences `request_uri`. Returns a signed Request Object JWT. */
  @Get('request/:id')
  @Header('Content-Type', 'application/oauth-authz-req+jwt')
  async requestObject(@Param('id') id: string): Promise<string> {
    try {
      return await this.platform.getOid4vp().requestObject(id);
    } catch (e) {
      toHttp(e);
    }
  }

  /**
   * The wallet posts the presentation (response_mode: direct_post).
   *
   * Before verifying, refresh the revocation snapshot: a presentation is exactly the
   * moment where a stale status list turns into a revoked credential being accepted.
   */
  @Post('response/:id')
  @HttpCode(200)
  async response(
    @Param('id') id: string,
    @Body() body: { vp_token?: unknown; state?: string },
  ) {
    try {
      for (const cfg of this.platform.listConfigs()) {
        await this.platform.syncStatusList(cfg);
      }
      const result = await this.platform.getOid4vp().handleResponse(id, body ?? {});
      const outcome = await this.platform.getOid4vp().result(id);
      const verdict = outcome.outcome as { valid?: boolean; reason?: string } | undefined;
      await this.platform.getAudit().record({
        action: 'oid4vp.presentation.verify',
        actor: 'wallet',
        outcome: verdict?.valid ? 'success' : 'failure',
        metadata: { requestId: id, reason: verdict?.valid ? undefined : verdict?.reason },
      });
      return result;
    } catch (e) {
      toHttp(e);
    }
  }

  /** The relying party polls for the verdict. */
  @Get('result/:id')
  @UseGuards(AdminKeyGuard)
  async result(@Param('id') id: string) {
    try {
      return await this.platform.getOid4vp().result(id);
    } catch (e) {
      toHttp(e);
    }
  }
}
