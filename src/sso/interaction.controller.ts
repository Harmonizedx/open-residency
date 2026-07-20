import { Body, Controller, Get, Inject, Post, Query, Req, Res } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import type Provider from 'oidc-provider';
import QRCode from 'qrcode';
import { PlatformService } from '../platform/platform.service';
import { loginPage, consentPage, cspHeader } from './interaction.views';

/**
 * The human-facing steps of the OIDC flow: sign-in and consent.
 *
 * Sign-in offers two real factors, replacing what used to be an existence check on the
 * residency ID (which was not authentication at all -- residency IDs are semi-public):
 *
 *   PRIMARY   a Verifiable Presentation. The citizen scans a QR with their wallet and
 *             presents their residency credential over OpenID4VP. The verifier proves
 *             holder binding, freshness, and audience, so the residency ID that comes
 *             back is authenticated, not merely asserted.
 *
 *   FALLBACK  a one-time code, for a citizen whose wallet is not to hand.
 *
 * All the authentication logic lives in the framework-agnostic SsoAuthService; this
 * controller is the thin HTTP/HTML layer over it.
 */
@Controller('interaction')
export class InteractionController {
  constructor(
    @Inject('OIDC_PROVIDER') private provider: Provider,
    private platform: PlatformService,
  ) {}

  @Get(':uid')
  async prompt(@Req() req: Request, @Res() res: Response) {
    const details = await this.provider.interactionDetails(req, res);
    const { prompt, params, uid } = details;

    const chrome = this.chromeFor(String(params.client_id ?? ''));
    if (prompt.name === 'login') {
      this.renderHtml(res, (nonce) => loginPage({ uid, nonce, ...chrome }));
      return;
    }
    if (prompt.name === 'consent') {
      this.renderHtml(res, (nonce) =>
        consentPage({ uid, nonce, scope: String(params.scope ?? ''), ...chrome }),
      );
      return;
    }
    res.status(400).end('Unknown prompt');
  }

  // ---- Primary factor: Verifiable Presentation ---------------------------

  /** Begin a presentation sign-in. Returns the request URI and a QR to render. */
  @Get(':uid/vp/start')
  async vpStart() {
    const { requestId, requestUri } = await this.platform.getSsoAuth().beginVpLogin();
    const qrSvg = await QRCode.toString(requestUri, { type: 'svg', margin: 1 });
    return { requestId, requestUri, qrSvg };
  }

  /** Poll a presentation sign-in. The wallet posts its response out of band. */
  @Get(':uid/vp/poll')
  async vpPoll(@Query('requestId') requestId: string) {
    const result = await this.platform.getSsoAuth().pollVpLogin(requestId);
    // Never leak the authenticated residentId to the poller; the browser does not need it,
    // and completion happens server-side against the interaction cookie.
    return { status: result.status };
  }

  /**
   * Complete a presentation sign-in. Called by the browser once polling reports success.
   *
   * Re-verifies server-side that the presentation for `requestId` actually authenticated,
   * so the request id -- which is the capability -- is what finishes the interaction, not
   * any client claim.
   */
  @Get(':uid/vp/complete')
  async vpComplete(@Query('requestId') requestId: string, @Req() req: Request, @Res() res: Response) {
    const result = await this.platform.getSsoAuth().pollVpLogin(requestId);
    if (result.status !== 'authenticated' || !result.residentId) {
      await this.renderLoginError(req, res, 'Sign-in not completed. Please try again.');
      return;
    }
    await this.finishLogin(req, res, result.residentId, 'vp');
  }

  // ---- Fallback factor: one-time code ------------------------------------

  /**
   * Request a one-time code. Responds identically whether or not the residency ID exists,
   * so it cannot be used to enumerate valid residency IDs.
   *
   * The catch is load-bearing, not defensive tidiness. Delivery now really happens, and it
   * fails for reasons that correlate with the resident EXISTING -- no contact number on
   * file, an aggregator rejection for that number -- while an unknown residency ID fails
   * silently and early. Letting those raise would answer 500 for a real resident and 200
   * for an invented one, which is a cleaner enumeration oracle than the one this endpoint
   * was written to avoid. The failure is recorded in the audit log instead, where an
   * operator can see it and the caller cannot.
   */
  @Post(':uid/otp/start')
  async otpStart(@Body() body: { residentId?: string }) {
    if (body?.residentId) {
      try {
        await this.platform.getSsoAuth().beginOtpLogin(body.residentId);
      } catch (e) {
        await this.platform.getAudit().record({
          action: 'sso.login',
          actor: body.residentId,
          outcome: 'failure',
          metadata: { factor: 'otp', stage: 'delivery', reason: (e as Error).message },
        });
      }
    }
    return { sent: true };
  }

  /** Verify a one-time code and, on success, complete the interaction. */
  @Post(':uid/otp/verify')
  async otpVerify(@Req() req: Request, @Res() res: Response) {
    const { residentId, code } = (req.body ?? {}) as { residentId?: string; code?: string };
    const result =
      residentId && code
        ? await this.platform.getSsoAuth().verifyOtpLogin(residentId, code)
        : { authenticated: false, reason: 'MISSING_FIELDS' };

    if (!result.authenticated || !result.residentId) {
      await this.platform.getAudit().record({
        action: 'sso.login',
        actor: residentId ?? 'unknown',
        outcome: 'failure',
        metadata: { factor: 'otp', reason: result.reason },
      });
      await this.renderLoginError(req, res, 'Incorrect or expired code. Please try again.');
      return;
    }
    await this.finishLogin(req, res, result.residentId, 'otp');
  }

  /** Shared completion: record the login and hand control back to the OIDC provider. */
  private async finishLogin(req: Request, res: Response, residentId: string, factor: string) {
    await this.platform.getAudit().record({
      action: 'sso.login',
      actor: residentId,
      target: residentId,
      outcome: 'success',
      metadata: { factor },
    });
    await this.provider.interactionFinished(
      req,
      res,
      { login: { accountId: residentId } },
      { mergeWithLastSubmission: false },
    );
  }

  private uidFromReq(req: Request): string {
    return String((req.params as { uid?: string }).uid ?? '');
  }

  // ---- Consent (unchanged) -----------------------------------------------

  @Post(':uid/confirm')
  async confirm(@Req() req: Request, @Res() res: Response) {
    const details = await this.provider.interactionDetails(req, res);
    const { params, session } = details as any;

    const accountId = session?.accountId as string;
    const clientId = String(params.client_id);
    const requested = String(params.scope ?? 'openid');

    // Reuse the grant this resident's active consent already authorizes, rather than
    // minting a fresh one on every sign-in. A new grant per login would leave the earlier
    // ones live and untracked, so withdrawing consent would revoke only the most recent
    // session. One consent record, one grant, revoked together.
    const resident = await this.platform.getStore().findByResidentId(accountId);
    const priorConsent = resident
      ? await this.platform.getConsent().findActive(resident.residentId, clientId)
      : null;
    const grant =
      (priorConsent?.grantId
        ? await this.provider.Grant.find(priorConsent.grantId)
        : undefined) ?? new this.provider.Grant({ accountId, clientId });
    grant.addOIDCScope(requested);
    const grantId = await grant.save();

    if (resident) {
      const scopes = requested.split(' ').filter((s) => s !== 'openid');
      const { record: consent } = await this.platform.getConsent().grant({
        residentId: resident.residentId,
        subjectRef: resident.subjectRef,
        relyingParty: clientId,
        purpose: `Cross-sector access requested by ${clientId}`,
        scopes,
        grantId,
      });
      await this.platform.getAudit().record({
        action: 'consent.grant',
        actor: resident.residentId,
        target: clientId,
        outcome: 'success',
        metadata: { scopes, consentId: consent.id, via: 'sso' },
      });
    }

    await this.provider.interactionFinished(
      req,
      res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true },
    );
  }

  @Get(':uid/abort')
  async abort(@Req() req: Request, @Res() res: Response) {
    await this.provider.interactionFinished(
      req,
      res,
      { error: 'access_denied', error_description: 'Citizen aborted the flow' },
      { mergeWithLastSubmission: false },
    );
  }

  // ---- View helpers -------------------------------------------------------

  /**
   * Send an HTML page under a per-response CSP that permits no inline script or style
   * except this response's nonce.
   *
   * This is the sign-in page for the whole platform, so it is the single most valuable
   * injection target in it. Escaping in the view layer is the primary defence; this header
   * is the one that still holds if an escape is ever missed. `default-src 'none'` means
   * anything not named below -- an injected <img>, a beacon, an iframe -- is simply not
   * fetched, and the absence of `unsafe-inline` is what makes the nonce meaningful at all.
   */
  private renderHtml(res: Response, render: (nonce: string) => string) {
    const nonce = randomBytes(16).toString('base64');
    res.set('content-type', 'text/html; charset=utf-8');
    res.set('content-security-policy', cspHeader(nonce));
    res.set('referrer-policy', 'no-referrer');
    res.set('x-content-type-options', 'nosniff');
    res.end(render(nonce));
  }

  /**
   * Re-render the sign-in page with an error, keeping the jurisdiction branding.
   *
   * The failing paths have no client_id to hand, so it is recovered from the interaction
   * session. If that lookup fails the interaction is already gone and the citizen will be
   * bounced anyway, so falling back to the default chrome is enough -- it must not throw
   * over cosmetics on an error page.
   */
  private async renderLoginError(req: Request, res: Response, error: string) {
    let uid = this.uidFromReq(req);
    let clientId = '';
    try {
      const details = await this.provider.interactionDetails(req, res);
      uid = String(details.uid);
      clientId = String(details.params.client_id ?? '');
    } catch {
      /* interaction expired or absent; default chrome is fine */
    }
    this.renderHtml(res, (nonce) =>
      loginPage({ uid, nonce, error, ...this.chromeFor(clientId) }),
    );
  }

  /**
   * Resolve the branding for a page from the relying party that initiated the flow.
   *
   * The jurisdiction is derived from the client, not assumed: this deployment can serve
   * several subnational units at once, and taking `listConfigs()[0]` would show every
   * citizen the first configured unit's name no matter which one they are signing in to.
   * The config that registers the relying party is the one whose citizen is at the keyboard.
   *
   * An unknown client yields no name at all rather than its raw client_id -- see the
   * consent view for why a bare identifier must not be presented as a service's name.
   */
  private chromeFor(clientId: string): { brand: string; clientName?: string } {
    const configs = this.platform.listConfigs();
    let tenant = configs[0];
    let clientName: string | undefined;
    if (clientId) {
      for (const c of configs) {
        const rp = c.oidc.relyingParties.find((r) => r.clientId === clientId);
        if (rp) {
          tenant = c;
          clientName = rp.name ?? rp.clientId;
          break;
        }
      }
    }
    return {
      brand: tenant?.credential.issuerName ?? 'Residency Single Sign-On',
      clientName,
    };
  }
}
