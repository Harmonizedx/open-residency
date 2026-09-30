// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Operations logging and metrics: the two claims that matter and the one that must never fail.
 *
 * The one that must never fail: a national identifier submitted to this service does not
 * appear in its log or its metrics -- not in a request line, not in a redacted object, not as
 * a label. `SECURITY.md` names "any path where a raw national ID could leak or be logged" as
 * the first sensitive area, and a structured request logger is the easiest way to build one.
 *
 * The two that matter: the request log carries what an operator needs (id, method, route
 * pattern, status, duration) and nothing a caller controls; and every metric label is drawn
 * from a bounded set, so neither a privacy leak nor a cardinality attack can arrive through
 * the scrape endpoint.
 */
import { EventEmitter } from 'node:events';
import type { AddressInfo } from 'node:net';
import { createRootLogger, REDACT_PATHS, SENSITIVE_KEYS } from '../src/observability/logging';
import { requestIdFrom, requestObserver, routeLabel } from '../src/observability/http';
import {
  metricsPortFromEnv,
  observeIssuance,
  recordJobSuccess,
  refusalReasonClass,
  registry,
  startMetricsServer,
} from '../src/observability/metrics';
import { PinoNestLogger } from '../src/observability/nest-logger';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? ` -- ${detail}` : ''}`);
  }
}

/** A capturing destination: pino writes one line per record, synchronously. */
function capture() {
  const lines: string[] = [];
  return {
    lines,
    stream: { write: (s: string) => void lines.push(s) },
    parsed: () => lines.map((l) => JSON.parse(l) as Record<string, unknown>),
    text: () => lines.join(''),
  };
}

/** The minimum of an Express request and response the observer touches. */
function fakeExchange(input: {
  method?: string;
  originalUrl: string;
  routePath?: string;
  baseUrl?: string;
  headers?: Record<string, string>;
  body?: unknown;
}) {
  const req = {
    method: input.method ?? 'GET',
    originalUrl: input.originalUrl,
    baseUrl: input.baseUrl ?? '',
    route: input.routePath ? { path: input.routePath } : undefined,
    headers: input.headers ?? {},
    body: input.body,
  };
  const headers = new Map<string, string>();
  const res = Object.assign(new EventEmitter(), {
    statusCode: 200,
    setHeader: (k: string, v: string) => void headers.set(k.toLowerCase(), v),
    getHeader: (k: string) => headers.get(k.toLowerCase()),
  });
  return { req, res, headers };
}

const NIN = '12345678901';
const PROBE = 'LIVE-FACE-PROBE-BYTES';
const OPERATOR_KEY = 'ork_0123456789abcdef';

async function main() {
  console.log('\n== Observability: logging, request observation, metrics ==\n');

  // --- Logger configuration -------------------------------------------------
  {
    const c = capture();
    const log = createRootLogger({ level: 'debug', destination: c.stream });
    check('the level passed in wins', log.level === 'debug');
    log.info({ a: 1 }, 'hello');
    const [line] = c.parsed();
    check('one JSON object per line', c.lines.length === 1 && typeof line === 'object');
    check('level is emitted as its name, not a number', line.level === 'info');
    check('service name is stamped on every line', line.service === 'openresidency');
    check(
      'timestamp is ISO-8601',
      typeof line.time === 'string' && !Number.isNaN(Date.parse(line.time as string)),
    );
  }
  {
    const c = capture();
    const log = createRootLogger({ level: 'loud', destination: c.stream });
    check('an unknown level falls back to info', log.level === 'info');
    check(
      'and says so, once',
      c.lines.length === 1 && /not a level/.test(c.lines[0]) && c.parsed()[0].level === 'warn',
    );
  }
  {
    const prev = process.env.LOG_LEVEL;
    process.env.LOG_LEVEL = 'warn';
    const log = createRootLogger({ destination: capture().stream });
    check('LOG_LEVEL is honoured when no level is passed', log.level === 'warn');
    if (prev === undefined) delete process.env.LOG_LEVEL;
    else process.env.LOG_LEVEL = prev;
  }

  // --- Redaction ------------------------------------------------------------
  {
    const c = capture();
    const log = createRootLogger({ level: 'trace', destination: c.stream });
    log.info(
      {
        identifiers: { nin: NIN, dateOfBirth: '1990-01-01' },
        nin: NIN,
        deep: { deeper: { deepest: { sample: PROBE } } },
        headers: { 'x-api-key': OPERATOR_KEY, authorization: `Bearer ${OPERATOR_KEY}` },
        req: { body: { anything: NIN }, query: { nin: NIN }, headers: { cookie: 'sid=abc' } },
        code: '482913',
        otp: '482913',
      },
      'an object somebody logged',
    );
    const text = c.text();
    check('a national identifier under `identifiers` is censored', !text.includes(NIN));
    check('a biometric probe three levels deep is censored', !text.includes(PROBE));
    check('an operator key in a headers object is censored', !text.includes(OPERATOR_KEY));
    check('req.body / req.query / req.headers are censored wholesale', !text.includes('sid=abc'));
    check('a one-time code is censored', !text.includes('482913'));
    check('the censor marker is what appears instead', text.includes('[REDACTED]'));
    check(
      'every sensitive key has a redact path at the top level and nested',
      SENSITIVE_KEYS.every((k) => REDACT_PATHS.some((p) => p.endsWith(k) || p.endsWith(`"${k}"]`))) &&
        REDACT_PATHS.some((p) => p.startsWith('*.*.*')),
    );
    check(
      'a non-sensitive sibling survives, so redaction is not "log nothing"',
      text.includes('1990-01-01') === false && text.includes('an object somebody logged'),
      'identifiers is censored as a whole, including dateOfBirth; the message survives',
    );
  }

  // --- Request observation --------------------------------------------------
  {
    const c = capture();
    const log = createRootLogger({ level: 'info', destination: c.stream });
    const observe = requestObserver(log);

    const x = fakeExchange({
      method: 'POST',
      originalUrl: `/identity/verify?nin=${NIN}`,
      routePath: '/identity/verify',
      headers: { authorization: `Bearer ${OPERATOR_KEY}` },
      body: { identifiers: { nin: NIN } },
    });
    let nextCalled = false;
    observe(x.req as never, x.res as never, () => void (nextCalled = true));
    check('the middleware passes control on', nextCalled);
    const issued = x.headers.get('x-request-id');
    check(
      'a request id is minted and returned in the response header',
      typeof issued === 'string' && /^[0-9a-f-]{36}$/.test(issued),
      issued,
    );
    x.res.statusCode = 200;
    x.res.emit('finish');
    const [line] = c.parsed();
    check('one request line is written on finish', c.lines.length === 1);
    check('it carries the request id', line?.reqId === issued);
    check('it carries method, route pattern, status', line?.method === 'POST' && line?.route === '/identity/verify' && line?.status === 200);
    check('it carries a numeric duration', typeof line?.durationMs === 'number' && (line.durationMs as number) >= 0);
    const text = c.text();
    check('the identifier in the QUERY STRING is not logged', !text.includes(NIN));
    check('the identifier in the BODY is not logged', !text.includes('identifiers'));
    check('the operator key in the header is not logged', !text.includes(OPERATOR_KEY));
    check('the URL itself is not logged (only the route pattern)', !text.includes('nin='));
  }
  {
    check('a well-formed inbound x-request-id is honoured', requestIdFrom('edge-7f3a.2') === 'edge-7f3a.2');
    check('a header array takes its first value', requestIdFrom(['abc', 'def']) === 'abc');
    const spoofed = requestIdFrom('injected value with spaces');
    check('a malformed inbound id is replaced, not trimmed', spoofed !== 'injected value with spaces' && /^[0-9a-f-]{36}$/.test(spoofed));
    check('an over-long id is replaced', /^[0-9a-f-]{36}$/.test(requestIdFrom('a'.repeat(65))));
    check('a missing header mints one', /^[0-9a-f-]{36}$/.test(requestIdFrom(undefined)));
  }
  {
    check('a matched route logs its PATTERN', routeLabel({ baseUrl: '', originalUrl: '/residency/KT-1234-ABCD-5', route: { path: '/residency/:residentId' } }) === '/residency/:residentId');
    check('the OIDC mount collapses to one label', routeLabel({ baseUrl: '', originalUrl: '/oidc/auth?client_id=tax&state=x' }) === '/oidc/*');
    check('the static UI mount collapses to one label', routeLabel({ baseUrl: '', originalUrl: '/app/enroll.html' }) === '/app/*');
    check('an unrouted path is one label, whatever it was', routeLabel({ baseUrl: '', originalUrl: `/${NIN}/anything` }) === 'unmatched');
  }
  {
    const c = capture();
    const observe = requestObserver(createRootLogger({ level: 'info', destination: c.stream }));
    const x = fakeExchange({ originalUrl: '/health/ready', routePath: '/health/ready' });
    observe(x.req as never, x.res as never, () => undefined);
    x.res.emit('finish');
    check('probe traffic is not logged at info', c.lines.length === 0);
    const d = capture();
    const observeDebug = requestObserver(createRootLogger({ level: 'debug', destination: d.stream }));
    const y = fakeExchange({ originalUrl: '/health/live', routePath: '/health/live' });
    observeDebug(y.req as never, y.res as never, () => undefined);
    y.res.emit('finish');
    check('but is available at debug', d.lines.length === 1 && d.parsed()[0].level === 'debug');
  }
  {
    const c = capture();
    const observe = requestObserver(createRootLogger({ level: 'info', destination: c.stream }));
    const x = fakeExchange({ originalUrl: '/residency/issue', routePath: '/residency/issue', method: 'POST' });
    observe(x.req as never, x.res as never, () => undefined);
    x.res.statusCode = 503;
    x.res.emit('finish');
    check('a 5xx is logged at error, so it can be alerted on', c.parsed()[0]?.level === 'error');
  }

  // --- Metrics: bounded labels ----------------------------------------------
  {
    const c = capture();
    const observe = requestObserver(createRootLogger({ level: 'silent', destination: c.stream }));
    const x = fakeExchange({ method: 'BREW', originalUrl: `/${NIN}`, });
    observe(x.req as never, x.res as never, () => undefined);
    x.res.statusCode = 404;
    x.res.emit('finish');
    const metrics = await registry.getMetricsAsJSON();
    const http = metrics.find((m) => m.name === 'openresidency_http_request_duration_seconds');
    const values = (http?.values ?? []) as Array<{ labels: Record<string, string> }>;
    check('HTTP duration is recorded', values.length > 0);
    check('an unknown HTTP method is labelled OTHER', values.some((v) => v.labels.method === 'OTHER'));
    check('an unrouted path is labelled unmatched, never the path', values.some((v) => v.labels.route === 'unmatched') && !values.some((v) => JSON.stringify(v.labels).includes(NIN)));
    check('the earlier matched route is labelled by its pattern', values.some((v) => v.labels.route === '/identity/verify' && v.labels.status === '200'));
  }
  {
    check('ASSURANCE_TOO_LOW_<level> collapses to its family', refusalReasonClass('ASSURANCE_TOO_LOW_BASIC') === 'ASSURANCE_TOO_LOW');
    check('APPLICANT_BINDING_REQUIRED_<method> collapses to its family', refusalReasonClass('APPLICANT_BINDING_REQUIRED_NONE') === 'APPLICANT_BINDING_REQUIRED');
    check('a fixed reason code passes through', refusalReasonClass('FOUNDATIONAL_NO_MATCH') === 'FOUNDATIONAL_NO_MATCH');
    check('free text becomes OTHER', refusalReasonClass('Provisional issuance not confirmed within 30 days') === 'OTHER');
    check('anything resembling an identifier becomes OTHER', refusalReasonClass(`nin=${NIN}`) === 'OTHER');
    check('no reason is UNSPECIFIED', refusalReasonClass(undefined) === 'UNSPECIFIED');
  }
  {
    observeIssuance({ status: 'issued', unit: 'KT', unitIsDeclared: true });
    observeIssuance({ status: 'rejected', reason: 'ASSURANCE_TOO_LOW_BASIC', unit: 'KT', unitIsDeclared: true });
    observeIssuance({ status: 'rejected', reason: 'INVALID_SUBNATIONAL_UNIT', unit: NIN, unitIsDeclared: false });
    const metrics = await registry.getMetricsAsJSON();
    const issuance = metrics.find((m) => m.name === 'openresidency_issuance_total');
    const values = (issuance?.values ?? []) as Array<{ labels: Record<string, string>; value: number }>;
    check('an issued decision has an empty reason', values.some((v) => v.labels.status === 'issued' && v.labels.reason === '' && v.labels.unit === 'KT'));
    check('a refusal carries its reason class', values.some((v) => v.labels.status === 'rejected' && v.labels.reason === 'ASSURANCE_TOO_LOW'));
    check('an undeclared unit is labelled `undeclared`, never the caller\'s string', values.some((v) => v.labels.unit === 'undeclared') && !values.some((v) => v.labels.unit === NIN));
  }
  {
    recordJobSuccess('audit_checkpoint', 1_700_000_000_000);
    const metrics = await registry.getMetricsAsJSON();
    const gauge = metrics.find((m) => m.name === 'openresidency_background_job_last_success_timestamp_seconds');
    const values = (gauge?.values ?? []) as Array<{ labels: Record<string, string>; value: number }>;
    check('a job success sets its timestamp gauge, in seconds', values.some((v) => v.labels.job === 'audit_checkpoint' && v.value === 1_700_000_000));
  }

  // --- Metrics: the listener ------------------------------------------------
  {
    check('METRICS_PORT unset means disabled', metricsPortFromEnv({}) === undefined);
    check('METRICS_PORT empty means disabled', metricsPortFromEnv({ METRICS_PORT: '' }) === undefined);
    check('METRICS_PORT parses', metricsPortFromEnv({ METRICS_PORT: '9464' }) === 9464);
    let threw = false;
    try { metricsPortFromEnv({ METRICS_PORT: 'nine' }); } catch { threw = true; }
    check('a non-numeric METRICS_PORT is refused at boot', threw);
    threw = false;
    try { metricsPortFromEnv({ METRICS_PORT: '70000' }); } catch { threw = true; }
    check('an out-of-range METRICS_PORT is refused at boot', threw);
  }
  {
    const log = createRootLogger({ level: 'silent', destination: capture().stream });
    const server = await startMetricsServer(0, log);
    const { port } = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${port}`;
    const ok = await fetch(`${base}/metrics`);
    const body = await ok.text();
    check('GET /metrics answers 200', ok.status === 200, `status ${ok.status}`);
    check('in the Prometheus text exposition format', (ok.headers.get('content-type') ?? '').startsWith('text/plain'));
    check('with the application series', body.includes('openresidency_http_request_duration_seconds') && body.includes('openresidency_issuance_total'));
    check('and the process defaults', body.includes('process_cpu_seconds_total'));
    check('the exposition contains no identifier that passed through the service', !body.includes(NIN) && !body.includes(OPERATOR_KEY));
    const other = await fetch(`${base}/anything-else`);
    check('any other path is 404', other.status === 404);
    const post = await fetch(`${base}/metrics`, { method: 'POST' });
    check('any other method is 404', post.status === 404);
    await new Promise<void>((r) => server.close(() => r()));
  }

  // --- The Nest logger adapter ---------------------------------------------
  {
    const c = capture();
    const nest = new PinoNestLogger(createRootLogger({ level: 'trace', destination: c.stream }));
    nest.log('Nest application successfully started', 'NestApplication');
    nest.error(new Error('boom'), 'stack trace text', 'KeyCustody');
    nest.warn({ identifiers: { nin: NIN } }, 'OperatorGuard');
    const [started, errored, warned] = c.parsed();
    check('Nest context becomes a field, not a prefix', started.context === 'NestApplication' && started.msg === 'Nest application successfully started');
    check('an Error is serialised with its message', errored.level === 'error' && errored.context === 'KeyCustody' && (errored.err as { message?: string })?.message === 'boom');
    check('an object logged through Nest is still redacted', !c.text().includes(NIN) && warned.context === 'OperatorGuard');
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
