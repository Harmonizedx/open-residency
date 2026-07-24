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

// ---------------------------------------------------------------------------
// Bring-your-own matcher over HTTP.
//
// A deployment points this at whatever attests biometric matches for its jurisdiction --
// a national ABIS, a MOSIP gateway, a vendor SDK behind an HTTP shim -- exactly as it
// points `foundational` at its national ID API and `messaging` at its SMS aggregator.
// The request shape and where the verdict lives in the response are declared in config,
// so no code changes to onboard a new authority.
// ---------------------------------------------------------------------------

export type BiometricProviderCode = 'NONE' | 'MOCK' | 'GENERIC_HTTP';

export interface BiometricHttpConfig {
  provider: BiometricProviderCode;
  /** Base URL of the authority. Required for GENERIC_HTTP. */
  baseUrl?: string;
  timeoutMs?: number;
  /** Attesting-authority name recorded in the audit trail (or read from the response). */
  source?: string;
  auth?: {
    type: 'none' | 'apiKey' | 'bearer' | 'basic';
    headerName?: string;
    secretEnv?: string;
    usernameEnv?: string;
  };
  request?: {
    method?: 'POST' | 'GET';
    /** Path with {residentId}/{modality} placeholders. */
    path?: string;
    /** JSON body with {residentId}/{modality}/{sample} placeholders. */
    bodyTemplate?: Record<string, string>;
    headers?: Record<string, string>;
    /** Where the yes/no verdict lives, and the value that means "matched". */
    matchedFlag?: { path: string; equals?: unknown };
    /** Dot-path to a 0..1 score, if the authority reports one. */
    scorePath?: string;
    /** Dot-path to the authority's own name in the response, overriding `source`. */
    sourcePath?: string;
  };
}

function readAt(obj: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined),
      obj,
    );
}

function fill(template: string, capture: BiometricCapture): string {
  return template
    .replace(/\{residentId\}/g, encodeURIComponent(capture.residentId))
    .replace(/\{modality\}/g, capture.modality)
    // The live sample is substituted ONLY into the outbound request to the authority. It is
    // never returned, logged, or stored; that is the whole custody model.
    .replace(/\{sample\}/g, capture.sample);
}

function biometricAuthHeaders(cfg: BiometricHttpConfig): Record<string, string> {
  const auth = cfg.auth;
  if (!auth || auth.type === 'none') return {};
  const secret = auth.secretEnv ? process.env[auth.secretEnv] : undefined;
  if (!secret) throw new Error(`biometric auth secret ${auth.secretEnv ?? '<unset>'} is not set in the environment`);
  switch (auth.type) {
    case 'apiKey':
      return { [auth.headerName ?? 'x-api-key']: secret };
    case 'bearer':
      return { authorization: `Bearer ${secret}` };
    case 'basic': {
      const user = auth.usernameEnv ? process.env[auth.usernameEnv] : undefined;
      if (!user) throw new Error(`biometric auth username ${auth.usernameEnv ?? '<unset>'} is not set`);
      return { authorization: `Basic ${Buffer.from(`${user}:${secret}`).toString('base64')}` };
    }
  }
}

/**
 * Config-driven biometric matcher over HTTP.
 *
 * FAIL-CLOSED is the load-bearing property and the reason this is not a copy of the
 * messaging provider: messaging THROWS on a delivery failure, but here a thrown error, a
 * timeout, a non-2xx, or a malformed response must all resolve to `matched: false` with a
 * reason -- never propagate as something a caller could mistake for a pass. At AAL3 a
 * false positive is account takeover, so "we could not confirm" and "confirmed" must be
 * impossible to confuse.
 *
 * PRIVACY: the capture is sent to the authority and nowhere else. It is not returned in
 * the result, not logged here, and callers must keep it out of the audit trail.
 */
export class GenericHttpBiometricMatcher implements BiometricMatcher {
  constructor(
    private cfg: BiometricHttpConfig,
    private fetchImpl: typeof fetch = fetch,
  ) {
    if (!cfg.baseUrl) throw new Error('biometric GENERIC_HTTP needs a baseUrl');
    if (!cfg.request?.matchedFlag) throw new Error('biometric GENERIC_HTTP needs request.matchedFlag');
  }

  async match(capture: BiometricCapture): Promise<BiometricMatchResult> {
    const req = this.cfg.request!;
    const source = this.cfg.source ?? 'biometric-authority';
    const fail = (reason: string): BiometricMatchResult => ({
      matched: false,
      source,
      modality: capture.modality,
      reason,
    });

    let body: unknown;
    try {
      const url = new URL(fill(req.path ?? '', capture), this.cfg.baseUrl).toString();
      const jsonBody: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.bodyTemplate ?? {})) jsonBody[k] = fill(v, capture);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 8000);
      let res: Response;
      try {
        res = await this.fetchImpl(url, {
          method: req.method ?? 'POST',
          headers: { 'content-type': 'application/json', ...biometricAuthHeaders(this.cfg), ...(req.headers ?? {}) },
          body: (req.method ?? 'POST') === 'GET' ? undefined : JSON.stringify(jsonBody),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      // A non-2xx is "could not confirm", never a pass.
      if (!res.ok) return fail(`HTTP_${res.status}`);
      body = await res.json();
    } catch (e) {
      // Network error, timeout/abort, or non-JSON body: fail closed.
      return fail((e as Error).name === 'AbortError' ? 'TIMEOUT' : 'SERVICE_UNAVAILABLE');
    }

    const verdict = readAt(body, req.matchedFlag!.path);
    const expected = req.matchedFlag!.equals ?? true;
    const matched = verdict === expected;
    const score = req.scorePath ? Number(readAt(body, req.scorePath)) : undefined;
    const attested = req.sourcePath ? readAt(body, req.sourcePath) : undefined;

    return {
      matched,
      score: Number.isFinite(score) ? score : undefined,
      source: typeof attested === 'string' && attested ? attested : source,
      modality: capture.modality,
      reason: matched ? undefined : 'NO_MATCH',
    };
  }
}

/**
 * Build the matcher for a deployment from config. `NONE` yields no matcher (biometric
 * step-up is simply unavailable -- a deployment without a biometric authority does not
 * offer AAL3). `MOCK` is dev/test only.
 */
export function buildBiometricMatcher(
  cfg: BiometricHttpConfig | undefined,
  fetchImpl: typeof fetch = fetch,
): BiometricMatcher | null {
  if (!cfg || cfg.provider === 'NONE') return null;
  if (cfg.provider === 'MOCK') return new MockBiometricMatcher(cfg.source);
  if (cfg.provider === 'GENERIC_HTTP') return new GenericHttpBiometricMatcher(cfg, fetchImpl);
  throw new Error(`unknown biometric provider "${(cfg as { provider: string }).provider}"`);
}
