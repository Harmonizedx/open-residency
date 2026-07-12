/**
 * Framework-agnostic contracts for foundational identity verification.
 *
 * The whole point of this layer: OpenResidency never assumes a specific national
 * ID. NIN, Aadhaar, Huduma Namba, Ghana Card, National ID of any country are all
 * just *providers* behind one interface. A new country is onboarded by adding a
 * YAML config (and, only if the provider is exotic, a small adapter), never by
 * touching the residency, credential, or SSO layers.
 */

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
}

export interface FoundationalVerificationResult {
  verified: boolean;
  providerCode: string;
  assuranceLevel: AssuranceLevel;
  identity?: NormalizedIdentity;
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
