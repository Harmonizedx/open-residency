import axios, { AxiosInstance } from 'axios';
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  NormalizedIdentity,
  ProviderConfig,
} from '../types';
import { getPath, interpolate, interpolateObject, tokenizeSubject } from '../util';

/**
 * A foundational provider that is driven ENTIRELY by configuration.
 *
 * For the large majority of national ID verification APIs (a single REST call that
 * takes an id + demographic and returns a match plus attributes) no code is needed:
 * you describe the request, the success flag, and the attribute mapping in the
 * country's YAML, and this adapter does the rest. That is what makes OpenResidency
 * reusable across countries without forking.
 *
 * Providers with genuinely non-REST or multi-step semantics (Aadhaar OTP, mTLS
 * token exchange) get a thin dedicated adapter that can still reuse this mapping.
 */
export class GenericRestAdapter implements FoundationalProvider {
  readonly code: string;
  private cfg!: ProviderConfig;
  private http!: AxiosInstance;
  private pepper: string;

  constructor(code = 'GENERIC_REST', pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.code = code;
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
    this.http = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeoutMs ?? 8000,
    });
  }

  private authHeaders(): Record<string, string> {
    const auth = this.cfg.auth;
    if (!auth || auth.type === 'none') return {};
    const secret = auth.secretEnv ? process.env[auth.secretEnv] : undefined;
    switch (auth.type) {
      case 'apiKey':
        return { [auth.headerName ?? 'x-api-key']: secret ?? '' };
      case 'bearer':
        return { authorization: `Bearer ${secret ?? ''}` };
      case 'basic': {
        const id = auth.clientIdEnv ? process.env[auth.clientIdEnv] : '';
        const pw = auth.clientSecretEnv ? process.env[auth.clientSecretEnv] : '';
        return {
          authorization: 'Basic ' + Buffer.from(`${id}:${pw}`).toString('base64'),
        };
      }
      default:
        return {};
    }
  }

  private mapIdentity(
    responseBody: unknown,
    input: FoundationalVerificationInput,
  ): NormalizedIdentity {
    const m = this.cfg.responseMapping ?? {};
    const pick = (field: keyof NormalizedIdentity): string | undefined => {
      const path = m[field];
      if (!path) return undefined;
      const v = getPath(responseBody, path);
      return v == null ? undefined : String(v);
    };

    // The raw foundational identifier: prefer a mapped subject path, else the first
    // submitted identifier. Either way it is tokenized before it leaves this adapter.
    const rawSubjectPath = (this.cfg.extra?.subjectSourcePath as string) ?? undefined;
    const rawId =
      (rawSubjectPath ? String(getPath(responseBody, rawSubjectPath) ?? '') : '') ||
      Object.values(input.identifiers)[0] ||
      '';

    return {
      subjectRef: tokenizeSubject(this.code, rawId, this.pepper),
      fullName: pick('fullName'),
      givenName: pick('givenName'),
      familyName: pick('familyName'),
      dateOfBirth: pick('dateOfBirth'),
      gender: pick('gender'),
      phone: pick('phone'),
      email: pick('email'),
      photo: pick('photo'),
      addressHint: pick('addressHint'),
    };
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const req = this.cfg.request ?? {};
    const scope = { identifiers: input.identifiers, context: input.context ?? {} };
    const path = interpolate(req.path ?? '', scope);
    const headers = { ...interpolateObject(req.headers, scope), ...this.authHeaders() };

    try {
      const res =
        (req.method ?? 'POST') === 'GET'
          ? await this.http.get(path, { headers })
          : await this.http.post(path, interpolateObject(req.bodyTemplate, scope), {
              headers,
            });

      const body = res.data;
      const flag = this.cfg.verifiedFlag;
      let verified = true;
      if (flag) {
        const actual = getPath(body, flag.path);
        verified =
          flag.equals === undefined ? Boolean(actual) : actual === flag.equals;
      }

      if (!verified) {
        return {
          verified: false,
          providerCode: this.code,
          assuranceLevel: 'none',
          reason: 'FOUNDATIONAL_NO_MATCH',
        };
      }

      return {
        verified: true,
        providerCode: this.code,
        assuranceLevel: this.cfg.assuranceOnSuccess ?? 'verified',
        identity: this.mapIdentity(body, input),
        // Only providers that actually authenticate the owner (an eID/OIDC redirect, or an
        // OTP to the registered device) attest binding. A plain lookup does not: it leaves
        // applicantBinding undefined so the residency engine will not mistake a matched
        // record for a proven owner.
        applicantBinding: this.cfg.authenticatesApplicant
          ? {
              method: 'authoritative_authentication',
              ref: input.challengeRef,
              verifiedAt: new Date().toISOString(),
            }
          : undefined,
      };
    } catch (err: unknown) {
      const status = axios.isAxiosError(err) ? err.response?.status : undefined;
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: status ? `PROVIDER_HTTP_${status}` : 'PROVIDER_UNREACHABLE',
      };
    }
  }
}
