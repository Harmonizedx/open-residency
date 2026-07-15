import { Oid4vpService } from '../oid4vp/oid4vp-service';
import { ResidencyStore } from '../residency/ports';
import { OtpService } from './otp';

/**
 * Authentication for the residency IdP.
 *
 * This is the fix for a real hole. The previous login handler took a residency ID, checked
 * that the record EXISTED, and issued an authenticated cross-sector session. Residency IDs
 * are semi-public by design -- printed on cards, carried in QR codes -- so that was not
 * authentication at all: anyone who knew someone's residency ID could sign in as them to
 * Health, Tax, and Subsidy. This service replaces the existence check with two real
 * factors.
 *
 * PRIMARY -- Verifiable Presentation. The citizen presents their own residency credential
 * from a wallet, over OpenID4VP. That already proves holder binding (they hold the key the
 * credential was issued to), freshness (a nonce we chose), and audience (us). The residency
 * ID in the verified presentation is therefore an AUTHENTICATED identity, not an asserted
 * one. This reuses the exact verifier the rest of the platform uses, so a credential that
 * would fail at a clinic fails at sign-in too -- including revocation.
 *
 * FALLBACK -- one-time code. For a citizen whose wallet is not to hand. Weaker, but it
 * keeps sign-in reachable for someone with only a feature phone, which is an inclusion
 * requirement. See otp.ts for the code lifecycle and the privacy boundary around delivery.
 */
export class SsoAuthService {
  constructor(
    private oid4vp: Oid4vpService,
    private otp: OtpService,
    private residents: ResidencyStore,
  ) {}

  // ---- Primary: Verifiable Presentation ----------------------------------

  /**
   * Begin a presentation-based sign-in. Returns a request the login page renders as a QR
   * for the citizen's wallet to scan.
   */
  async beginVpLogin(): Promise<{ requestId: string; requestUri: string }> {
    const req = await this.oid4vp.createRequest({ purpose: 'Sign in with your residency credential' });
    return { requestId: req.requestId, requestUri: req.requestUri };
  }

  /**
   * Poll a presentation-based sign-in.
   *
   * The wallet posts its presentation to the OpenID4VP response endpoint out of band; the
   * login page polls this until the presentation has been verified. On success the
   * authenticated residency ID is returned, and the caller completes the OIDC interaction
   * with it.
   */
  async pollVpLogin(
    requestId: string,
  ): Promise<{ status: 'pending' | 'authenticated' | 'failed'; residentId?: string; reason?: string }> {
    // An unknown or expired request id must read as a clean failure, not a 500. Otherwise
    // polling a made-up id -- which an attacker will do -- throws instead of denying.
    let result: Record<string, unknown>;
    try {
      result = await this.oid4vp.result(requestId);
    } catch {
      return { status: 'failed', reason: 'UNKNOWN_REQUEST' };
    }
    if (result.status === 'pending') return { status: 'pending' };

    const outcome = result.outcome as
      | { valid?: boolean; reason?: string; claims?: { residentId?: string } }
      | undefined;

    if (result.status !== 'fulfilled' || !outcome?.valid) {
      return { status: 'failed', reason: outcome?.reason ?? 'PRESENTATION_INVALID' };
    }

    const residentId = outcome.claims?.residentId;
    if (!residentId) return { status: 'failed', reason: 'NO_RESIDENT_ID' };

    // The presentation verified, but confirm the resident still exists in this register:
    // a credential can outlive the record it was issued from (a different deployment, a
    // purged register). Sign-in must reflect the register, not just the credential.
    const record = await this.residents.findByResidentId(residentId);
    if (!record) return { status: 'failed', reason: 'UNKNOWN_RESIDENT' };

    return { status: 'authenticated', residentId };
  }

  // ---- Fallback: one-time code -------------------------------------------

  /**
   * Send a one-time code for a residency ID.
   *
   * Note what this does NOT do: it does not reveal whether the residency ID exists. A code
   * is "sent" either way, and the response is identical, so this endpoint cannot be used to
   * enumerate valid residency IDs. Only a resident who actually receives the code (on the
   * contact the deployment has on file) can proceed.
   */
  async beginOtpLogin(residentId: string): Promise<void> {
    const record = await this.residents.findByResidentId(residentId);
    if (!record) return; // silently no-op: do not confirm or deny existence
    await this.otp.issue(residentId);
  }

  /** Verify a submitted one-time code. */
  async verifyOtpLogin(
    residentId: string,
    code: string,
  ): Promise<{ authenticated: boolean; residentId?: string; reason?: string }> {
    const result = await this.otp.verify(residentId, code);
    if (!result.ok) return { authenticated: false, reason: result.reason };
    return { authenticated: true, residentId: result.residentId };
  }
}
