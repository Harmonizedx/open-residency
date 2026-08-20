// SPDX-License-Identifier: Apache-2.0
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  NormalizedIdentity,
  ProviderConfig,
} from '../types';
import { tokenizeSubject } from '../util';
// Type-only: this adapter is handed a client, it never constructs one, so nothing in the
// foundational context depends on the oidc context at run time.
import type { UpstreamOidcClient } from '../../oidc/upstream-oidc';

/**
 * An OpenID Connect provider as a foundational source.
 *
 * Most registers here are a request and a response. This one is a redirect: the applicant
 * authenticates at the OP and comes back, and only then is there anything to read. That is
 * the same two-step shape Aadhaar's OTP needed, so it uses the same seam --
 * `initiateChallenge()` hands back the authorization URL, `verify()` consumes the callback --
 * and needs no new endpoint.
 *
 * SPEAKS THE STANDARD, NAMES NO VENDOR. eSignet is the OP this is most often pointed at, and
 * there is no eSignet-specific branch here; `ESIGNET` is an alias for discoverability, the
 * way `IMPORT` aliases `DATASET_FILE`.
 *
 * WHAT IT KEYS ON, AND WHY THAT IS NOT THE SUBJECT (ADR-0010). The residency identity is
 * derived from the authoritative identifier the OP releases -- a national identifier mapped
 * through `claimMapping.nationalId` -- and never from the OP's `sub`. A `sub` is pairwise per
 * relying party: it is a different value for every RP by design, so tokenizing it would
 * produce an identity that changes if this deployment ever re-registers, and that a
 * registrar enrolling the same person through a register lookup could never reproduce.
 *
 * So an OP that authenticates but releases no identifier cannot be a foundational source.
 * This adapter refuses rather than falling back to `sub`, because the fallback is precisely
 * the failure it exists to avoid, and it would fail silently years later at the point where
 * two records for one person cannot be reconciled.
 */
export class OidcFoundationalAdapter implements FoundationalProvider {
  readonly code: string;
  private cfg?: ProviderConfig;

  constructor(
    code: string,
    private client?: UpstreamOidcClient,
    private pepper: string = process.env.SUBJECT_PEPPER ?? 'dev-pepper',
  ) {
    this.code = code;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
  }

  /**
   * Step one: where to send the applicant.
   *
   * `type: 'push'` because the applicant completes this out of band, at the OP, exactly as
   * they would approve a push notification -- there is no code for them to read back to an
   * operator. `channel` carries the authorization URL and `challengeRef` the `state`, which
   * the client already treats as single-use.
   */
  async initiateChallenge(
    _input: FoundationalVerificationInput,
  ): Promise<{ type: 'otp' | 'biometric' | 'push'; channel: string; challengeRef: string }> {
    if (!this.client) throw new Error(this.notConfigured());
    const start = await this.client.beginLogin();
    return { type: 'push', channel: start.authorizationUrl, challengeRef: start.state };
  }

  /**
   * Step two: turn the callback into a foundational result.
   *
   * `identifiers.code` is the authorization code the OP redirected back with, and
   * `challengeRef` the `state` issued in step one. Everything that can go wrong returns a
   * reason rather than throwing: this runs behind an HTTP handler, and a thrown error there
   * becomes a 500, which reads as "retry" to a caller when most of these mean "do not".
   */
  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    if (!this.client) {
      return this.failed('UPSTREAM_OIDC_NOT_CONFIGURED');
    }
    const code = input.identifiers?.code;
    const state = input.challengeRef ?? input.identifiers?.state;
    if (!code || !state) {
      return this.failed('MISSING_CODE_OR_STATE');
    }

    const result = await this.client.completeLogin({ code, state });
    if (!result.authenticated || !result.identity) {
      return this.failed(result.reason ?? 'UPSTREAM_AUTHENTICATION_FAILED');
    }

    const authoritativeId = result.identity.nationalId;
    if (!authoritativeId) {
      // Fails closed. See the class comment: `sub` is not a substitute, and accepting the
      // sign-in without an identifier would write a record nothing else can match.
      return this.failed('NO_AUTHORITATIVE_IDENTIFIER');
    }

    const identity: NormalizedIdentity = {
      subjectRef: tokenizeSubject(this.code, authoritativeId, this.pepper),
      fullName: result.identity.fullName,
      givenName: result.identity.givenName,
      familyName: result.identity.familyName,
      dateOfBirth: result.identity.dateOfBirth,
      gender: result.identity.gender,
      phone: result.identity.phone,
      email: result.identity.email,
      photo: result.identity.photo,
      addressHint: result.identity.addressHint,
    };

    return {
      verified: true,
      providerCode: this.code,
      assuranceLevel: result.assurance ?? this.cfg?.assuranceOnSuccess ?? 'verified',
      identity,
      // The redirect authenticated the applicant as the owner of this identity, which is
      // exactly what an applicant->identity binding records. Unlike a bare lookup, this
      // adapter has standing to assert one.
      applicantBinding: result.binding,
    };
  }

  private failed(reason: string): FoundationalVerificationResult {
    return {
      verified: false,
      providerCode: this.code,
      assuranceLevel: 'none',
      reason,
    };
  }

  private notConfigured(): string {
    return (
      `foundational provider '${this.code}' needs an upstream OIDC profile: declare the ` +
      `OP under the deployment's upstream config so the platform can build a client for it`
    );
  }
}
