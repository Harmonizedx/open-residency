import { Controller, Get, Inject, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import type Provider from 'oidc-provider';
import { PlatformService } from '../platform/platform.service';

/**
 * Handles the human-facing steps of the OIDC flow: login and consent.
 *
 * IMPORTANT (authentication factor): the demo login below only checks that a
 * Residency ID exists. That is NOT authentication. A real deployment binds one of:
 *   - an SMS/USSD one-time code sent to the phone bound to the residency (works on
 *     feature phones, see the offline module), or
 *   - a Verifiable Presentation of the resident's own residency credential from a
 *     wallet (strongest, and fully offline-capable).
 * The place to enforce that is the `login` handler, where noted.
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

    if (prompt.name === 'login') {
      res.set('content-type', 'text/html');
      res.end(this.loginPage(uid, String(params.client_id ?? '')));
      return;
    }

    // Consent step: show which residency claims will be shared, then confirm.
    if (prompt.name === 'consent') {
      res.set('content-type', 'text/html');
      res.end(this.consentPage(uid, String(params.client_id ?? ''), (params.scope as string) ?? ''));
      return;
    }

    res.status(400).end('Unknown prompt');
  }

  @Post(':uid/login')
  async login(@Req() req: Request, @Res() res: Response) {
    const { residentId } = (req.body ?? {}) as { residentId?: string };

    // ---- Authentication happens here. Demo: existence check only. ----
    const record = residentId
      ? await this.platform.getStore().findByResidentId(residentId)
      : null;

    if (!record) {
      res.set('content-type', 'text/html');
      res.end(this.loginPage('', '', 'Residency ID not found. Try again.'));
      return;
    }
    // In production: verify OTP or a Verifiable Presentation before proceeding.

    const result = { login: { accountId: record.residentId } };
    await this.platform.getAudit().record({
      action: 'sso.login',
      actor: record.residentId,
      target: record.residentId,
      outcome: 'success',
    });
    await this.provider.interactionFinished(req, res, result, {
      mergeWithLastSubmission: false,
    });
  }

  @Post(':uid/confirm')
  async confirm(@Req() req: Request, @Res() res: Response) {
    const details = await this.provider.interactionDetails(req, res);
    const { prompt, params, session } = details as any;

    const accountId = session?.accountId as string;
    const clientId = String(params.client_id);
    const requested = String(params.scope ?? 'openid');

    const grant = new this.provider.Grant({ accountId, clientId });
    grant.addOIDCScope(requested);
    const grantId = await grant.save();

    // Record a first-class, revocable consent and mint a portable receipt.
    const resident = await this.platform.getStore().findByResidentId(accountId);
    if (resident) {
      const scopes = requested.split(' ').filter((s) => s !== 'openid');
      const { record: consent } = await this.platform.getConsent().grant({
        residentId: resident.residentId,
        subjectRef: resident.subjectRef,
        relyingParty: clientId,
        purpose: `Cross-sector access requested by ${clientId}`,
        scopes,
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
    void prompt;
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

  private loginPage(uid: string, clientId: string, error = ''): string {
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title></head><body style="font-family:system-ui;max-width:420px;margin:40px auto;padding:0 16px">
<h2>Sign in to continue</h2>
<p style="color:#555">Service <b>${clientId}</b> is requesting to verify your residency.</p>
${error ? `<p style="color:#b00">${error}</p>` : ''}
<form method="post" action="/interaction/${uid}/login">
  <label>Residency ID<br><input name="residentId" placeholder="KT-XXXX-XXXX-X" style="width:100%;padding:8px;font-size:16px"></label>
  <p style="color:#777;font-size:13px">A one-time code will be sent to your registered phone (production).</p>
  <button type="submit" style="padding:10px 16px;font-size:16px">Continue</button>
</form></body></html>`;
  }

  private consentPage(uid: string, clientId: string, scope: string): string {
    const claims = scope
      .split(' ')
      .filter((s) => s !== 'openid')
      .join(', ');
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consent</title></head><body style="font-family:system-ui;max-width:420px;margin:40px auto;padding:0 16px">
<h2>Share your residency?</h2>
<p><b>${clientId}</b> would like to access: <b>${claims || 'basic profile'}</b>.</p>
<p style="color:#777;font-size:13px">Your national ID number is never shared. Only your residency status and the details above.</p>
<form method="post" action="/interaction/${uid}/confirm">
  <button type="submit" style="padding:10px 16px;font-size:16px">Allow</button>
  <a href="/interaction/${uid}/abort" style="margin-left:12px">Deny</a>
</form></body></html>`;
  }
}
