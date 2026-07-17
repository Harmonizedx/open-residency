/**
 * Applicant -> identity binding.
 *
 * Foundational verification answers two questions: does this identity record exist, and
 * is it genuine (resolution + evidence validation). It does NOT answer the third question
 * identity proofing depends on: is the person in front of us the RIGHTFUL OWNER of that
 * identity? NIST 800-63A keeps these separate on purpose, and collapsing them is the
 * classic proofing error -- a bare registry lookup (submit a number, get back a name)
 * binds nothing, because anyone who knows the number passes it.
 *
 * Binding is established by an additional, independent act tied to the owner:
 *   - the owner authenticating at the source (an eID / OIDC redirect, or an OTP delivered
 *     to the device registered against that identity);
 *   - a live biometric captured from the applicant and matched to the authoritative
 *     portrait or template held by the identity source;
 *   - an enrolment agent comparing the applicant to the evidence in person.
 *
 * The residency engine records which of these happened, and refuses to treat a passed
 * lookup as owner proof.
 */

export type BindingMethod =
  /** Owner authenticated at the source: eID / OIDC redirect, or OTP to the registered device. */
  | 'authoritative_authentication'
  /** Live capture matched to the authoritative portrait, with liveness / PAD. */
  | 'face_match'
  /** 1:1 fingerprint or iris match performed by the identity source. */
  | 'fingerprint_match'
  /** An enrolment agent compared the applicant to the evidence in person. */
  | 'attended_comparison'
  /** No binding performed: foundational lookup only. Not owner proof. */
  | 'none';

export interface ApplicantBinding {
  method: BindingMethod;
  /** Opaque reference to the binding act: an auth transaction, a match id, an operator id. */
  ref?: string;
  /** ISO timestamp of when binding occurred. */
  verifiedAt?: string;
  /** For biometric methods, the achieved match score if the subsystem reports one. */
  score?: number;
}

/**
 * Strength ordering. A higher rank binds the applicant to the identity more strongly.
 * face_match and fingerprint_match are peers; authoritative authentication at the source
 * is strongest because the source itself vouched that the owner was present.
 */
export const BINDING_RANK: Record<BindingMethod, number> = {
  none: 0,
  attended_comparison: 1,
  face_match: 2,
  fingerprint_match: 2,
  authoritative_authentication: 3,
};

export const NO_BINDING: ApplicantBinding = { method: 'none' };

/** The stronger of two bindings; ties keep the first argument. */
export function strongestBinding(a?: ApplicantBinding, b?: ApplicantBinding): ApplicantBinding {
  const x = a ?? NO_BINDING;
  const y = b ?? NO_BINDING;
  return BINDING_RANK[y.method] > BINDING_RANK[x.method] ? y : x;
}

/** Whether an achieved binding satisfies a policy's list of accepted methods. */
export function bindingSatisfies(binding: ApplicantBinding, accepted: BindingMethod[]): boolean {
  return binding.method !== 'none' && accepted.includes(binding.method);
}
