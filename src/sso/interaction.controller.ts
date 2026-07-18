import { Body, Controller, Get, Inject, Post, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import type Provider from 'oidc-provider';
import QRCode from 'qrcode';
import { PlatformService } from '../platform/platform.service';

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

    if (prompt.name === 'login') {
      res.set('content-type', 'text/html');
      res.end(this.loginPage(uid, String(params.client_id ?? '')));
      return;
    }
    if (prompt.name === 'consent') {
      res.set('content-type', 'text/html');
      res.end(this.consentPage(uid, String(params.client_id ?? ''), (params.scope as string) ?? ''));
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
      res.set('content-type', 'text/html');
      res.end(this.loginPage(this.uidFromReq(req), '', 'Sign-in not completed. Please try again.'));
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
      res.set('content-type', 'text/html');
      res.end(this.loginPage(this.uidFromReq(req), '', 'Incorrect or expired code. Please try again.'));
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

  // ---- HTML ---------------------------------------------------------------

  /**
   * The sign-in page. Two tabs: scan-to-sign-in (VP, primary) and use-a-code (OTP).
   *
   * The VP tab fetches a presentation request, renders its QR, and polls until the wallet
   * has responded, then navigates to the completion endpoint. Kept to inline vanilla JS so
   * there is no build step; a production deployment would replace this with its own themed
   * front end, but the endpoints it drives are the real ones.
   */
  private loginPage(uid: string, clientId: string, error = ''): string {
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title></head><body style="font-family:system-ui;max-width:460px;margin:40px auto;padding:0 16px">
<h2>Sign in to continue</h2>
${clientId ? `<p style="color:#555">Service <b>${clientId}</b> is requesting to verify your residency.</p>` : ''}
${error ? `<p style="color:#b00">${error}</p>` : ''}

<div style="display:flex;gap:8px;margin:16px 0">
  <button id="tab-vp" onclick="show('vp')" style="flex:1;padding:8px">Scan with wallet</button>
  <button id="tab-otp" onclick="show('otp')" style="flex:1;padding:8px">Use a one-time code</button>
</div>

<div id="pane-vp">
  <p style="color:#555">Scan this with your wallet to present your residency credential.</p>
  <div id="qr" style="max-width:260px">Loading&hellip;</div>
  <p id="vp-status" style="color:#777;font-size:13px">Waiting for your wallet&hellip;</p>
</div>

<div id="pane-otp" style="display:none">
  <form id="otp-start" onsubmit="return sendCode(event)">
    <label>Residency ID<br><input id="rid" name="residentId" placeholder="KT-XXXX-XXXX-X" style="width:100%;padding:8px;font-size:16px"></label>
    <button type="submit" style="margin-top:8px;padding:10px 16px;font-size:16px">Send me a code</button>
  </form>
  <form id="otp-verify" method="post" action="/interaction/${uid}/otp/verify" style="display:none;margin-top:16px">
    <input type="hidden" id="rid2" name="residentId">
    <label>Enter the code sent to your registered contact<br><input name="code" inputmode="numeric" style="width:100%;padding:8px;font-size:16px"></label>
    <button type="submit" style="margin-top:8px;padding:10px 16px;font-size:16px">Sign in</button>
  </form>
</div>

<script>
const uid = ${JSON.stringify(uid)};
function show(which){
  document.getElementById('pane-vp').style.display = which==='vp'?'block':'none';
  document.getElementById('pane-otp').style.display = which==='otp'?'block':'none';
  if (which==='vp') startVp();
}
let polling=false;
async function startVp(){
  if (polling) return; polling=true;
  const r = await fetch('/interaction/'+uid+'/vp/start');
  const { requestId, qrSvg } = await r.json();
  document.getElementById('qr').innerHTML = qrSvg;
  const tick = async () => {
    const p = await (await fetch('/interaction/'+uid+'/vp/poll?requestId='+encodeURIComponent(requestId))).json();
    if (p.status==='authenticated'){ window.location = '/interaction/'+uid+'/vp/complete?requestId='+encodeURIComponent(requestId); return; }
    if (p.status==='failed'){ document.getElementById('vp-status').textContent='Presentation was not accepted. Refresh to try again.'; return; }
    setTimeout(tick, 2000);
  };
  setTimeout(tick, 2000);
}
async function sendCode(e){
  e.preventDefault();
  const rid = document.getElementById('rid').value.trim();
  await fetch('/interaction/'+uid+'/otp/start', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({residentId:rid})});
  document.getElementById('rid2').value = rid;
  document.getElementById('otp-start').style.display='none';
  document.getElementById('otp-verify').style.display='block';
  return false;
}
show('vp');
</script>
</body></html>`;
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
