/**
 * Authentication assurance, and how sign-in factors combine into it.
 *
 * The residency IdP now offers factors of very different strength: a one-time code
 * (phishable, single factor), a Verifiable Presentation (proves possession of the holder
 * key the credential was bound to), a WebAuthn passkey (possession + phishing-resistant),
 * and an attested authoritative biometric match (something-you-are, checked against the
 * source of record). A relying party that only issues a permit needs less than one that
 * authorises a benefits payment, so the id_token has to *say* how strongly the citizen
 * authenticated -- not just that they did.
 *
 * That is expressed with the standard OIDC `acr` (a level) and `amr` (the methods used,
 * RFC 8176). A relying party reads `acr` to decide whether to step the citizen up before a
 * sensitive action. Without this, every sign-in looked identical to an RP regardless of
 * whether it was a code typed into a page or a hardware passkey plus a biometric.
 */

export type AuthFactor = 'otp' | 'vp' | 'webauthn' | 'biometric';

/** NIST-style authenticator assurance level, 1 (lowest) to 3 (highest). */
export type Aal = 1 | 2 | 3;

export interface AssuranceResult {
  /** OIDC acr value. A stable URN an RP can compare or map to policy. */
  acr: string;
  /** OIDC amr values (RFC 8176): the methods actually used. */
  amr: string[];
  aal: Aal;
  /** True when at least one phishing-resistant factor (WebAuthn) was used. */
  phishingResistant: boolean;
}

const ACR_PREFIX = 'urn:openresidency:aal';

/** RFC 8176 authentication-method references for each factor. */
const AMR: Record<AuthFactor, string[]> = {
  otp: ['otp'],
  vp: ['pop'], // proof-of-possession of the holder key bound to the credential
  webauthn: ['hwk', 'user', 'pop'], // hardware key, user present, possession
  biometric: ['bio'],
};

/**
 * Combine the factors a sign-in actually used into an assurance result.
 *
 * The level is the strongest justified by the combination, not a sum of prompts:
 *   - AAL3: a phishing-resistant possession factor (WebAuthn) AND an attested biometric
 *           match against the authoritative source -- possession + inherence, verifier-
 *           impersonation-resistant.
 *   - AAL2: a bound-key possession factor on its own (WebAuthn, or a Verifiable
 *           Presentation whose holder binding was proven).
 *   - AAL1: a single phishable factor (a one-time code).
 *
 * An empty factor set is AAL0-equivalent and rejected by the caller, never issued.
 */
export function assess(factors: AuthFactor[]): AssuranceResult {
  const set = new Set(factors);
  const phishingResistant = set.has('webauthn');
  const possession = set.has('webauthn') || set.has('vp');

  let aal: Aal;
  if (phishingResistant && set.has('biometric')) aal = 3;
  else if (possession) aal = 2;
  else aal = 1;

  const amr = [...new Set(factors.flatMap((f) => AMR[f]))].sort();
  return { acr: `${ACR_PREFIX}${aal}`, amr, aal, phishingResistant };
}

/** Does an achieved assurance meet or exceed what a relying party asked for? */
export function meetsRequirement(achieved: AssuranceResult, requiredAcr: string): boolean {
  const req = /aal([1-3])$/.exec(requiredAcr);
  if (!req) return false;
  return achieved.aal >= Number(req[1]);
}
