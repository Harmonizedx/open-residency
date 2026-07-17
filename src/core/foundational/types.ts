/**
 * Framework-agnostic contracts for foundational identity verification.
 *
 * The whole point of this layer: OpenResidency never assumes a specific national
 * ID. NIN, Aadhaar, Huduma Namba, Ghana Card, National ID of any country are all
 * just *providers* behind one interface. A new country is onboarded by adding a
 * YAML config (and, only if the provider is exotic, a small adapter), never by
 * touching the residency, credential, or SSO layers.
 */

import { ApplicantBinding } from '../proofing/binding';

export type AssuranceLevel = 'none' | 'basic' | 'verified' | 'high';

/** What the citizen (or an operator on their behalf) submits to prove foundational identity. */
export interface FoundationalVerificationInput {
  countryCode: string;
  /**
   * Identifier bundle. Keys are declared per-country in config `foundational.inputs`.
   * Examples:
   *   Nigeria (NIN):   { nin: '12345678901', dateOfBirth: '1990-01-01' }
   *   India (Aadhaar): { aadhaar: '999999990019', otp: '123456' }
   *   Kenya (Huduma):  { hudumaNumber: 'HK...', firstName, lastName }
   */
  identifiers: Record<string, string>;
  /** Optional second-factor transaction reference returned from initiateChallenge(). */
  challengeRef?: string;
  /** Free-form context (channel, operator id, consent receipt id, etc.). */
  context?: Record<string, unknown>;
}

/**
 * Provider-agnostic identity shape. Adapters map their raw response into this.
 * Raw provider payloads are deliberately NOT propagated downstream: only mapped,
 * minimized attributes leave the adapter, which keeps PII handling auditable.
 */
export interface NormalizedIdentity {
  /**
   * A stable, provider-scoped reference to the individual. This is NOT the raw
   * national ID number. Adapters must return a tokenized / hashed reference so
   * the residency store never persists the raw foundational number.
   */
  subjectRef: string;
  fullName?: string;
  givenName?: string;
  familyName?: string;
  dateOfBirth?: string;
  gender?: string;
  phone?: string;
  email?: string;
  /** Base64 portrait if the provider returns one and policy permits storing it. */
  photo?: string;
  /** Provider-reported address, used only as a hint; residency is proven separately. */
  addressHint?: string;
  /**
   * Provider-reported CURRENT residence locality (state / province / LGA / ...). This is
   * residence *evidence* -- usually self-declared to the source register and often stale --
   * NOT proof. The residency engine offers it to the proof-of-residence policy as
   * `register_declared_residence`, capped and reconciled against the claimed unit.
   */
  residenceAdminUnit?: string;
  /**
   * Provider-reported state / place of ORIGIN (indigeneity, heritage). This is NOT
   * residence and must never be used to prove it -- doing so encodes indigene-vs-settler
   * discrimination. Captured separately so it can never be mistaken for residence, and by
   * default it is not carried into the residency credential at all.
   */
  originAdminUnit?: string;
}

export interface FoundationalVerificationResult {
  verified: boolean;
  providerCode: string;
  assuranceLevel: AssuranceLevel;
  identity?: NormalizedIdentity;
  /**
   * Set only when the verification act itself authenticated the applicant as the OWNER
   * of this identity -- an eID / OIDC redirect, or an OTP delivered to the device
   * registered against the record. A bare lookup adapter leaves this undefined: passing
   * the lookup proves the record is genuine, not that the applicant owns it. The
   * residency engine reads this as one possible source of applicant->identity binding.
   */
  applicantBinding?: ApplicantBinding;
  /** When the provider needs a second factor (OTP / biometric) before it will confirm. */
  pendingChallenge?: { type: 'otp' | 'biometric' | 'push'; channel: string; challengeRef: string };
  /** Machine-readable reason on failure, safe to surface to operators. */
  reason?: string;
}

/** Static configuration handed to an adapter at init time (comes from country YAML). */
export interface ProviderConfig {
  code: string;
  /** Base URL of the foundational verification API. */
  baseUrl?: string;
  /** Auth mode against the foundational API. */
  auth?: {
    type: 'none' | 'apiKey' | 'bearer' | 'basic' | 'mtls';
    headerName?: string;
    secretEnv?: string; // env var name that holds the secret, never the secret itself
    tokenUrl?: string; // for OAuth client-credentials providers
    clientIdEnv?: string;
    clientSecretEnv?: string;
  };
  timeoutMs?: number;
  /** Generic-REST adapters use these to shape the request/response. */
  request?: {
    method?: 'GET' | 'POST';
    path?: string; // appended to baseUrl; may contain {placeholders} from identifiers
    bodyTemplate?: Record<string, string>; // values may reference {identifiers.x}
    headers?: Record<string, string>;
  };
  /** Dot-path mapping from provider response JSON -> NormalizedIdentity fields. */
  responseMapping?: Partial<Record<keyof NormalizedIdentity, string>>;
  /** Dot-path in the response that signals success, plus the value that means "verified". */
  verifiedFlag?: { path: string; equals?: unknown };
  /** Assurance level this provider yields on success. */
  assuranceOnSuccess?: AssuranceLevel;
  /**
   * Declares that this provider's verification authenticates the applicant as the OWNER
   * (an eID / OIDC redirect, or an OTP to the registered device), not merely that the
   * record exists. When true, a successful verify() attests
   * `authoritative_authentication` binding. Lookup-only providers must leave this false.
   */
  authenticatesApplicant?: boolean;
  /** Adapter-specific extras. */
  extra?: Record<string, unknown>;
}

/**
 * The single interface every country integration implements.
 * Keep it small on purpose: verify() plus an optional two-step challenge.
 */
export interface FoundationalProvider {
  readonly code: string;
  init(config: ProviderConfig): void | Promise<void>;
  verify(input: FoundationalVerificationInput): Promise<FoundationalVerificationResult>;
  /** Optional: kick off OTP/biometric before verify() can succeed (e.g. Aadhaar OTP). */
  initiateChallenge?(
    input: FoundationalVerificationInput,
  ): Promise<{ type: 'otp' | 'biometric' | 'push'; channel: string; challengeRef: string }>;
}
