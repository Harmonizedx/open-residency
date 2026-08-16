// SPDX-License-Identifier: Apache-2.0
import axios, { AxiosInstance } from 'axios';
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';
import { interpolate, interpolateObject } from '../util';
import { buildAuthHeaders, resultFromBody } from '../mapping';
import { RetryPolicy, resolveRetryPolicy, withRetry } from '../retry';

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
 * XML/SOAP sources use GenericXmlAdapter; register extracts use DatasetFileAdapter --
 * both share the same mapping module as this one.
 */
export class GenericRestAdapter implements FoundationalProvider {
  readonly code: string;
  private cfg!: ProviderConfig;
  private http!: AxiosInstance;
  private pepper: string;
  private retry!: RetryPolicy;

  constructor(code = 'GENERIC_REST', pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.code = code;
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
    this.retry = resolveRetryPolicy(config.retry);
    this.http = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeoutMs ?? 8000,
    });
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const req = this.cfg.request ?? {};
    const scope = { identifiers: input.identifiers, context: input.context ?? {} };
    const path = interpolate(req.path ?? '', scope);
    const headers = { ...interpolateObject(req.headers, scope), ...buildAuthHeaders(this.cfg) };

    try {
      // Retried as a unit. A verification lookup is a read, so a repeat is safe: the far
      // end either never saw the first attempt or has nothing to undo.
      const res = await withRetry(
        () =>
          (req.method ?? 'POST') === 'GET'
            ? this.http.get(path, { headers })
            : this.http.post(path, interpolateObject(req.bodyTemplate, scope), { headers }),
        this.retry,
      );

      return resultFromBody(this.cfg, this.code, this.pepper, res.data, input);
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