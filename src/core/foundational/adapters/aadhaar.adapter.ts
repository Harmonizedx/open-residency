import { GenericRestAdapter } from './generic-rest.adapter';
import {
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';

/**
 * India Aadhaar adapter (illustrative).
 *
 * Aadhaar authentication commonly uses an OTP flow: you request an OTP tied to the
 * Aadhaar number, the resident receives it on their registered mobile, then you
 * submit number + OTP to authenticate. This adapter shows how a genuinely two-step
 * provider fits the same FoundationalProvider interface via initiateChallenge():
 *
 *   POST /residency/verify (no otp)  -> pendingChallenge { challengeRef }
 *   ... resident receives OTP ...
 *   POST /residency/verify (with otp + challengeRef) -> verified
 *
 * Endpoints/mapping still come from config; only the OTP orchestration is custom.
 */
export class AadhaarAdapter extends GenericRestAdapter {
  constructor(pepper?: string) {
    super('IN_AADHAAR', pepper);
  }

  init(config: ProviderConfig): void {
    super.init(config);
  }

  async initiateChallenge(input: FoundationalVerificationInput) {
    const aadhaar = (input.identifiers.aadhaar ?? '').replace(/\s/g, '');
    if (!/^\d{12}$/.test(aadhaar)) {
      throw new Error('INVALID_AADHAAR_FORMAT');
    }
    // In production: call the OTP-generation endpoint and return its txn id.
    // Here we return a deterministic-looking reference so the flow is testable.
    const challengeRef = `otp_${aadhaar.slice(-4)}_${Date.now().toString(36)}`;
    return { type: 'otp' as const, channel: 'sms', challengeRef };
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const aadhaar = (input.identifiers.aadhaar ?? '').replace(/\s/g, '');
    if (!/^\d{12}$/.test(aadhaar)) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: 'INVALID_AADHAAR_FORMAT',
      };
    }
    if (!input.identifiers.otp || !input.challengeRef) {
      const challenge = await this.initiateChallenge(input);
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        pendingChallenge: challenge,
        reason: 'OTP_REQUIRED',
      };
    }
    return super.verify(input);
  }
}
