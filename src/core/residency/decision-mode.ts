// SPDX-License-Identifier: Apache-2.0

import { BindingMethod } from '../proofing/binding';
import { ResidenceEvidenceMethod } from '../proofing/residence';

/**
 * Was this enrolment decision taken by a person, or by the software alone?
 *
 * Derived, never declared. A jurisdiction already chooses by saying which evidence and binding
 * methods it accepts: one that accepts only `face_match` and `document` has chosen automation,
 * one that requires `attended_comparison` has chosen a person. A separate `mode:` switch in
 * config would be a second source of truth that could contradict the methods -- a deployment
 * declaring `attended` while accepting a biometric match would be asserting something untrue
 * about how its decisions are actually made, and nothing would catch it.
 *
 * So the mode is computed from what actually happened, and a past decision stays auditable
 * because `binding.method` and `residence.method` are on the record.
 *
 * ## Why this matters legally
 *
 * A decision to grant or refuse residency gates access to services, so it carries legal or
 * similarly significant effects. Three regimes converge on the same rule for such decisions:
 *
 *   - **Nigeria, NDPA 2023 §37** -- a right not to be subject to a decision based solely on
 *     automated processing, with exceptions (contract, authorised by law, explicit consent)
 *     that do NOT remove the safeguards.
 *   - **EU, GDPR Article 22** -- the same right, the same shape.
 *   - **Council of Europe, Convention 108+** -- likewise.
 *
 * In every one, the safeguard is the same: the person may obtain **human intervention**,
 * express their point of view, and contest the decision. The reviewer must hold genuine
 * authority to reach a different outcome -- a review that cannot overturn is not a review.
 *
 * This module decides only whether a decision *was* automated. What a deployment owes the
 * person when it was is enforced at config load, and served by the refusal review path.
 */

export type DecisionMode = 'attended' | 'automated';

/**
 * Methods that require a person to have looked at the applicant or vouched for them.
 *
 * `authoritative_authentication` is deliberately NOT here. The owner authenticating at the
 * source -- an eID redirect, an OTP to their registered device -- is strong evidence, and it
 * is strong *without a human in this jurisdiction being involved*. It raises assurance and
 * leaves the decision automated, which is exactly the combination the safeguards exist for:
 * a confident machine decision is still a machine decision.
 */
const ATTENDED_BINDING: BindingMethod[] = ['attended_comparison'];

/** Residence evidence that required a person to vouch. */
const ATTENDED_RESIDENCE: ResidenceEvidenceMethod[] = ['authority_attestation'];

/**
 * The mode of a single decision, from the methods it actually used.
 *
 * Attended if EITHER limb involved a person: an operator who compared the applicant to the
 * record, or one who attested that they live in the unit. Both limbs machine-only means
 * nobody looked at this person before the register decided about them.
 */
export function decisionModeFor(input: {
  binding: { method: BindingMethod };
  residence: { method: ResidenceEvidenceMethod };
}): DecisionMode {
  const humanBound = ATTENDED_BINDING.includes(input.binding.method);
  const humanAttested = ATTENDED_RESIDENCE.includes(input.residence.method);
  return humanBound || humanAttested ? 'attended' : 'automated';
}

/**
 * Could this jurisdiction's policy produce a fully automated decision?
 *
 * Asked of the CONFIG rather than of a decision, so a deployment can be held to its
 * obligations before it takes any. True when neither limb obliges a person: an applicant
 * could be enrolled or refused end to end with nobody having looked at them.
 *
 * `bindingRequired` false means binding is optional, so an unbound applicant can be issued --
 * no person involved on that limb either.
 */
export function permitsAutomatedDecisions(policy: {
  bindingRequired: boolean;
  acceptedBindingMethods: BindingMethod[];
  acceptedResidenceMethods: ResidenceEvidenceMethod[];
}): boolean {
  const bindingCanSkipHuman =
    !policy.bindingRequired ||
    policy.acceptedBindingMethods.some((m) => !ATTENDED_BINDING.includes(m));
  const residenceCanSkipHuman = policy.acceptedResidenceMethods.some(
    (m) => !ATTENDED_RESIDENCE.includes(m),
  );
  return bindingCanSkipHuman && residenceCanSkipHuman;
}

/**
 * What `decidedBy` records when no person was involved.
 *
 * Carries the policy version, so the decision remains reproducible: "the software decided,
 * under this exact ruleset". An operator identity would be a lie, and a bare "system" would
 * lose the one thing that makes an automated decision auditable at all.
 */
export function automatedDecider(policyVersion: string): string {
  return `automated:${policyVersion}`;
}

export function isAutomatedDecider(decidedBy: string): boolean {
  return decidedBy.startsWith('automated:');
}
