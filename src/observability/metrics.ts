// SPDX-License-Identifier: Apache-2.0
import { createServer, Server } from 'node:http';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import type { Logger } from 'pino';

/**
 * Prometheus metrics, and the separate listener that serves them.
 *
 * ## What is measured
 *
 * The questions an operator has to be able to answer without reading logs: is the service
 * taking requests and how slowly; are enrolments being issued or refused, and for what class
 * of reason; is the foundational identity source answering; are the background jobs that
 * protect decaying guarantees (audit checkpoints, peer revocation sync, OIDC expiry sweeps)
 * still running. Alert on the last one by its timestamp ceasing to advance.
 *
 * ## What is deliberately not measured
 *
 * Anything about a person. No label carries a residentId, a subjectRef, a phone number, or a
 * value derived from one. Every label set below is enumerable from code or from the
 * jurisdiction's own config -- route PATTERNS not paths, a refusal reason CLASS not the full
 * string, a declared subnational unit code or the word `undeclared`. That is a privacy rule
 * and a cardinality rule at once: a label a caller can influence is a label a caller can use
 * to exhaust the metrics store.
 *
 * ## Where it is served
 *
 * On its own port (`METRICS_PORT`), never on the application port. Counts of enrolments and
 * refusals by ward describe a deployment's activity in real time, and the ingress routes only
 * to the application port -- so `/metrics` is reachable by the scraper inside the cluster and
 * by nothing outside it, without a single ingress rule having to be remembered. Unset, nothing
 * listens.
 */

export const registry = new Registry();
collectDefaultMetrics({ register: registry });

const httpRequestDuration = new Histogram({
  name: 'openresidency_http_request_duration_seconds',
  help: 'HTTP request duration by method, route pattern and status code',
  labelNames: ['method', 'route', 'status'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

const issuanceTotal = new Counter({
  name: 'openresidency_issuance_total',
  help: 'Residency issuance decisions by outcome, refusal reason class and subnational unit',
  labelNames: ['status', 'reason', 'unit'] as const,
  registers: [registry],
});

const verificationTotal = new Counter({
  name: 'openresidency_foundational_verification_total',
  help: 'Foundational identity verifications by provider code and outcome',
  labelNames: ['provider', 'outcome'] as const,
  registers: [registry],
});

const verificationDuration = new Histogram({
  name: 'openresidency_foundational_verification_duration_seconds',
  help: 'Round trip to the foundational identity source, by provider code',
  labelNames: ['provider'] as const,
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16],
  registers: [registry],
});

const jobLastSuccess = new Gauge({
  name: 'openresidency_background_job_last_success_timestamp_seconds',
  help: 'Unix time of the last successful run of each background job; alert when it stops advancing',
  labelNames: ['job'] as const,
  registers: [registry],
});

const HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

/** Anything a client can send as a method that is not a method it is allowed to name. */
export function methodLabel(method: string): string {
  return HTTP_METHODS.has(method) ? method : 'OTHER';
}

/** Milliseconds since a `process.hrtime.bigint()` reading. */
export function elapsedMs(since: bigint): number {
  return Number(process.hrtime.bigint() - since) / 1e6;
}

export function observeHttpRequest(input: {
  method: string;
  route: string;
  status: number;
  durationMs: number;
}): void {
  httpRequestDuration.observe(
    { method: methodLabel(input.method), route: input.route, status: String(input.status) },
    input.durationMs / 1000,
  );
}

export type IssuanceStatus = 'issued' | 'exists' | 'challenge' | 'rejected';

/**
 * The class of a refusal reason, bounded.
 *
 * Reasons are UPPER_SNAKE codes, two families of which carry a dynamic suffix
 * (`ASSURANCE_TOO_LOW_<level>`, `APPLICANT_BINDING_REQUIRED_<method>`); the suffix is dropped
 * so the family is one series. Anything that is not code-shaped -- a gateway's error text
 * surfacing as a reason, say -- becomes `OTHER` rather than a label value nobody chose.
 */
export function refusalReasonClass(reason: string | undefined): string {
  if (!reason) return 'UNSPECIFIED';
  for (const family of ['ASSURANCE_TOO_LOW', 'APPLICANT_BINDING_REQUIRED']) {
    if (reason.startsWith(`${family}_`)) return family;
  }
  return /^[A-Z][A-Z0-9_]{1,63}$/.test(reason) ? reason : 'OTHER';
}

export function observeIssuance(input: {
  status: IssuanceStatus;
  reason?: string;
  /** The unit the caller named. Used as a label only when the jurisdiction declares it. */
  unit: string;
  unitIsDeclared: boolean;
}): void {
  issuanceTotal.inc({
    status: input.status,
    reason: input.status === 'rejected' ? refusalReasonClass(input.reason) : '',
    unit: input.unitIsDeclared ? input.unit : 'undeclared',
  });
}

export type VerificationOutcome = 'verified' | 'rejected' | 'challenge' | 'error';

export function observeVerification(input: {
  provider: string;
  outcome: VerificationOutcome;
  durationMs: number;
}): void {
  verificationTotal.inc({ provider: input.provider, outcome: input.outcome });
  verificationDuration.observe({ provider: input.provider }, input.durationMs / 1000);
}

export type BackgroundJob = 'audit_checkpoint' | 'federation_status_refresh' | 'oidc_purge';

export function recordJobSuccess(job: BackgroundJob, at: number = Date.now()): void {
  jobLastSuccess.set({ job }, at / 1000);
}

/**
 * `METRICS_PORT` parsed, or undefined when unset. A value that is not a port is refused at
 * boot rather than silently leaving the service unobservable.
 */
export function metricsPortFromEnv(env: NodeJS.ProcessEnv = process.env): number | undefined {
  const raw = env.METRICS_PORT;
  if (raw === undefined || raw === '') return undefined;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`METRICS_PORT must be a TCP port number, got "${raw}"`);
  }
  return port;
}

/**
 * A minimal HTTP listener that answers `GET /metrics` and nothing else. Plain node:http rather
 * than a second Nest application: it has one route, and it must keep answering while the
 * application port is saturated, which a shared event loop cannot promise but a shared
 * middleware stack would make worse.
 */
export function startMetricsServer(
  port: number,
  log: Logger,
  reg: Registry = registry,
): Promise<Server> {
  const server = createServer((req, res) => {
    const path = (req.url ?? '').split('?')[0];
    if (req.method !== 'GET' || path !== '/metrics') {
      res.statusCode = 404;
      res.end();
      return;
    }
    reg
      .metrics()
      .then((body) => {
        res.setHeader('content-type', reg.contentType);
        res.end(body);
      })
      .catch((err: unknown) => {
        log.error({ err }, 'metrics scrape failed');
        res.statusCode = 500;
        res.end();
      });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}
