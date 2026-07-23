import { Body, Controller, Post } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';

/**
 * Passkey ENROLLMENT, standalone from any OIDC login.
 *
 * The security boundary this controller exists to enforce: a passkey is a possession
 * factor, so enrolling one for a residentId lets its holder sign in as that resident.
 * Enrollment therefore must be authorized by an already-proven factor. Here that is the
 * one-time code delivered to the resident's registered number -- the resident requests a
 * code (the existing /interaction flow's otp/start, or any code channel), then presents it
 * here alongside the passkey attestation. The honest statement of the guarantee: you can
 * only enroll a passkey for a resident whose one-time code you can complete.
 *
 * Passkey AUTHENTICATION (using an enrolled passkey to sign in) lives on the interaction
 * controller instead, because it completes an OIDC login. Enrollment does not, so it is
 * its own route and returns plainly.
 */
@Controller('webauthn')
export class WebAuthnController {
  constructor(private platform: PlatformService) {}

  /**
   * Begin enrollment. Requires a valid one-time code for the resident: without it, no
   * registration challenge is issued, so an attacker cannot bind a passkey to a residentId
   * they do not control.
   */
  @Post('register/start')
  async registerStart(@Body() body: { residentId?: string; otpCode?: string }) {
    const { residentId, otpCode } = body ?? {};
    if (!residentId || !otpCode) {
      return { ok: false, reason: 'MISSING_FIELDS' };
    }
    // The one-time code is the enrollment authorization. verifyOtpLogin consumes it, so a
    // code authorizes exactly one enrollment attempt.
    const proof = await this.platform.getSsoAuth().verifyOtpLogin(residentId, otpCode);
    if (!proof.authenticated || !proof.residentId) {
      await this.platform.getAudit().record({
        action: 'webauthn.register',
        actor: residentId,
        outcome: 'failure',
        metadata: { stage: 'authorize', reason: proof.reason },
      });
      return { ok: false, reason: 'NOT_AUTHORIZED' };
    }
    const { challengeId, options } = await this.platform.getWebAuthn().startRegistration(proof.residentId);
    return { ok: true, challengeId, options };
  }

  /** Complete enrollment: verify the attestation and persist the passkey. */
  @Post('register/finish')
  async registerFinish(
    @Body()
    body: {
      challengeId?: string;
      residentId?: string;
      authData?: string;
      clientDataJSON?: string;
    },
  ) {
    const { challengeId, residentId, authData, clientDataJSON } = body ?? {};
    if (!challengeId || !residentId || !authData || !clientDataJSON) {
      return { ok: false, reason: 'MISSING_FIELDS' };
    }
    const result = await this.platform
      .getWebAuthn()
      .finishRegistration(challengeId, residentId, { authData, clientDataJSON });

    await this.platform.getAudit().record({
      action: 'webauthn.register',
      actor: residentId,
      target: residentId,
      outcome: result.ok ? 'success' : 'failure',
      metadata: result.ok ? { credentialId: result.credentialId } : { reason: result.reason },
    });
    return result;
  }
}