import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpException,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import { PlatformService } from '../platform/platform.service';
import { OperatorGuard, RequireRoles } from '../common/operator.guard';
import { Oid4vciError, PRE_AUTHORIZED_CODE_GRANT } from '../core/oid4vci/oid4vci-service';

/**
 * The OpenID4VCI HTTP surface.
 *
 * Everything here is thin: parse, delegate to the framework-agnostic Oid4vciService,
 * translate errors into the OAuth-style JSON error bodies the spec requires. The token
 * and credential endpoints must never be cached, hence Cache-Control on both.
 */

/** OpenID4VCI errors are `{error, error_description}` with a meaningful status code. */
function toHttp(e: unknown): never {
  if (e instanceof Oid4vciError) {
    throw new HttpException({ error: e.code, error_description: e.message }, e.status);
  }
  throw e;
}

@Controller('openid4vci')
export class Oid4vciController {
  constructor(private platform: PlatformService) {}

  /**
   * Create a Credential Offer for an already-enrolled resident.
   *
   * This is the operator-facing endpoint, not a wallet-facing one: the enrollment desk
   * calls it after the foundational ID check has passed, and shows the returned QR to
   * the citizen. It is guarded by the admin API key, because being able to mint offers
   * for arbitrary residents is equivalent to being able to issue their credentials.
   */
  @Post('offer')
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  async createOffer(@Body() body: { residentId?: string }) {
    if (!body?.residentId) {
      throw new HttpException(
        { error: 'invalid_request', error_description: 'residentId is required' },
        400,
      );
    }
    try {
      const offer = await this.platform.getOid4vci().createOffer(body.residentId);
      await this.platform.getAudit().record({
        action: 'oid4vci.offer.create',
        actor: 'operator',
        target: body.residentId,
        outcome: 'success',
        // Never the pre-authorized code or the tx_code: an audit log is not a place to
        // put credentials that are still live.
        metadata: { offerId: offer.offerId },
      });
      return offer;
    } catch (e) {
      toHttp(e);
    }
  }

  /**
   * Token Endpoint. Exchanges the pre-authorized code (+ tx_code) for an access token.
   *
   * Form-encoded, per OAuth 2.0. Wallets send `application/x-www-form-urlencoded`, which
   * Express's urlencoded parser turns into the same body object as JSON, so both work.
   */
  @Post('token')
  @HttpCode(200)
  async token(
    @Body() body: Record<string, string>,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    try {
      return await this.platform.getOid4vci().token({
        grantType: body.grant_type ?? PRE_AUTHORIZED_CODE_GRANT,
        preAuthorizedCode: body['pre-authorized_code'],
        txCode: body.tx_code,
      });
    } catch (e) {
      toHttp(e);
    }
  }

  /**
   * Nonce Endpoint (OpenID4VCI 1.0). Deliberately unauthenticated, per spec: a c_nonce
   * is not a secret capability, it is a freshness challenge. Rate limiting is handled by
   * the global throttler.
   */
  @Post('nonce')
  @HttpCode(200)
  async nonce(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.platform.getOid4vci().nonce();
  }

  /** Credential Endpoint. Accepts both the Draft 13 and the 1.0 request shapes. */
  @Post('credential')
  @HttpCode(200)
  async credential(
    @Headers('authorization') authorization: string | undefined,
    @Body() body: Record<string, unknown>,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    try {
      const result = await this.platform.getOid4vci().credential(authorization, body ?? {});
      await this.platform.getAudit().record({
        action: 'oid4vci.credential.issue',
        actor: 'wallet',
        outcome: 'success',
      });
      return result;
    } catch (e) {
      await this.platform.getAudit().record({
        action: 'oid4vci.credential.issue',
        actor: 'wallet',
        outcome: 'failure',
        metadata: { reason: e instanceof Oid4vciError ? e.code : 'error' },
      });
      toHttp(e);
    }
  }
}

/**
 * Metadata lives under /.well-known, which is a separate route root, so it needs its own
 * controller rather than a prefix on the one above.
 */
@Controller()
export class Oid4vciMetadataController {
  constructor(private platform: PlatformService) {}

  @Get('.well-known/openid-credential-issuer')
  credentialIssuerMetadata() {
    return this.platform.getOid4vci().credentialIssuerMetadata();
  }

  @Get('.well-known/oauth-authorization-server')
  authorizationServerMetadata() {
    return this.platform.getOid4vci().authorizationServerMetadata();
  }

  /**
   * Some wallets look for OpenID Connect discovery at this path and fall back to it when
   * the OAuth one 404s. Serving the same document costs nothing and removes a class of
   * "wallet cannot find the issuer" support tickets.
   */
  @Get('.well-known/openid-configuration')
  openidConfiguration() {
    return this.platform.getOid4vci().authorizationServerMetadata();
  }

  /**
   * The residency JSON-LD context.
   *
   * Credentials reference this by its canonical URL, and our canonicalizer resolves it
   * from a pinned local copy rather than fetching it. Publishing it here anyway means an
   * external verifier using a stock JSON-LD toolchain can dereference it the normal way.
   */
  @Get('contexts/residency/v1')
  residencyContext(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Content-Type', 'application/ld+json');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return this.platform.residencyContext();
  }
}
