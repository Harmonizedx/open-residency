/**
 * Attested authoritative biometric match, as a pluggable port.
 *
 * The strongest sign-in step-up is proving the person at the keyboard is the rightful
 * holder by matching a live capture against the biometric held by the AUTHORITATIVE
 * source -- the national ID's stored template -- not a copy this system keeps. That match
 * is performed by an external subsystem (a national biometric SDK, a MOSIP/ABIS gateway,
 * a vendor matcher). This deployment never holds the reference template; it asks the
 * authoritative service and trusts its verdict, exactly as foundational verification asks
 * the national ID API rather than reimplementing it.
 *
 * So this is an interface plus a mock, the same shape as every other external integration
 * here (the foundational providers, the external contact directory, the KMS signers). A
 * real deployment configures a concrete matcher; the mock lets the whole step-up flow --
 * and its assurance consequences -- be exercised without a biometric vendor in the loop.
 *
 * It is deliberately NOT a biometric-matching implementation. Doing 1:1 face or fingerprint
 * comparison in this process would mean holding reference templates, which is the thing the
 * design avoids. The port returns an ATTESTATION from the authority, not a raw comparison.
 */

export type BiometricModality = 'face' | 'fingerprint';

export interface BiometricCapture {
  /** The resident whose authoritative template the capture is matched against. */
  residentId: string;
  modality: BiometricModality;
  /** Opaque, transient capture (e.g. a base64 probe). Never stored by this system. */
  sample: string;
}

export interface BiometricMatchResult {
  matched: boolean;
  /** Match score if the authority reports one (0..1). Advisory; `matched` is the verdict. */
  score?: number;
  /** Which authoritative service attested the result, for the audit trail. */
  source: string;
  modality: BiometricModality;
  /** Set when `matched` is false, to distinguish "no match" from "service unavailable". */
  reason?: string;
}

export interface BiometricMatcher {
  /**
   * Ask the authoritative service whether this live capture matches the resident's
   * template. Implementations must fail closed: a service error is a non-match with a
   * reason, never a thrown 500 that a caller might read as success.
   */
  match(capture: BiometricCapture): Promise<BiometricMatchResult>;
}

/**
 * Development / test matcher. Deterministic, holds no templates, matches nobody by
 * default -- a capture matches only when its sample carries the agreed marker for the
 * resident, so a test can exercise both the match and the non-match path without a vendor.
 *
 * The marker scheme (`match:<residentId>`) is a stand-in for "the authority said yes"; it
 * is not, and must not be mistaken for, biometric comparison. Refuses to run when
 * NODE_ENV=production, so it cannot be the silently-inherited matcher in a real deployment.
 */
export class MockBiometricMatcher implements BiometricMatcher {
  constructor(private readonly source = 'mock-biometric-authority') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('MockBiometricMatcher must not be used in production: configure a real BiometricMatcher.');
    }
  }

  async match(capture: BiometricCapture): Promise<BiometricMatchResult> {
    const matched = capture.sample === `match:${capture.residentId}`;
    return {
      matched,
      score: matched ? 0.99 : 0.0,
      source: this.source,
      modality: capture.modality,
      reason: matched ? undefined : 'NO_MATCH',
    };
  }
}
