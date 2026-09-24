// SPDX-License-Identifier: Apache-2.0
import pino from 'pino';
import type { DestinationStream, Logger, LoggerOptions } from 'pino';

/**
 * The operations log: one JSON object per line, to stdout, for a log shipper to collect.
 *
 * This is NOT the audit log. `src/core/audit/audit-log.ts` is a tamper-evident record of what
 * happened to which residency -- kept for the auditor, retained for years, privacy-preserving
 * by construction. This is what an operator reads at three in the morning to find out why the
 * enrolment desks are slow: request timings, dependency failures, background-job outcomes.
 * Different readers, different retention, different content. The two must not be conflated,
 * because the pressure to grep the audit chain during an incident is exactly the pressure that
 * makes it grow fields it must never carry.
 *
 * ## What may never appear here
 *
 * A raw national identifier. `SECURITY.md` lists "any path where a raw national ID could leak
 * or be logged" as the first sensitive area, and structured logging makes that easier to get
 * wrong, not harder: a request logger that serialised `req.body` on `/identity/verify` would
 * record every NIN submitted. Two defences, both load-bearing:
 *
 *   1. The request logger (`http.ts`) never serialises bodies, query strings or headers. It
 *      logs method, route PATTERN, status and duration. Nothing sensitive is offered, so
 *      nothing has to be redacted.
 *   2. Redaction on the logger itself, for anything ELSE that logs an object -- a caught error
 *      carrying its request context, a debug line somebody adds later. The keys below are
 *      censored before serialisation, wherever they sit in the object.
 *
 * `scripts/observability-smoke.ts` asserts both.
 */

/**
 * Keys censored wherever they appear in a logged object, at the top level and up to three
 * levels down. `identifiers` is the applicant's national-ID submission; `sample` a live
 * biometric probe; `individualId` MOSIP's identifier; the rest are credentials of one kind or
 * another. `code` is broad on purpose: a one-time code and an OAuth authorization code are
 * both bearer secrets, and neither belongs in a log.
 */
export const SENSITIVE_KEYS: readonly string[] = [
  'identifiers',
  'nin',
  'aadhaar',
  'individualId',
  'sample',
  'password',
  'otp',
  'code',
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'client_secret',
  'access_token',
  'refresh_token',
  'id_token',
];

/** pino's redact paths take dotted keys, with bracket notation for anything not identifier-shaped. */
function segment(key: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `.${key}` : `["${key}"]`;
}

export const REDACT_PATHS: readonly string[] = [
  // Whole request sub-objects, should anything ever log one.
  'req.body',
  'req.query',
  'req.headers',
  ...SENSITIVE_KEYS.flatMap((key) => {
    const s = segment(key);
    return [s.replace(/^\./, ''), `*${s}`, `*.*${s}`, `*.*.*${s}`];
  }),
];

const LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LEVELS)[number];

export function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === 'string' && (LEVELS as readonly string[]).includes(value);
}

export interface RootLoggerOptions {
  /** Overrides `LOG_LEVEL`. An unknown value falls back to `info` and is reported once. */
  level?: string;
  /** Where lines go. Defaults to stdout; tests pass a capturing stream. */
  destination?: DestinationStream;
}

/**
 * The single logger the process writes through. Level from `LOG_LEVEL` (default `info`); level
 * emitted as its name rather than pino's numeric code, because every shipper reads the name and
 * nobody remembers that 30 means info.
 */
export function createRootLogger(opts: RootLoggerOptions = {}): Logger {
  const requested = opts.level ?? process.env.LOG_LEVEL ?? 'info';
  const level: LogLevel = isLogLevel(requested) ? requested : 'info';
  const options: LoggerOptions = {
    level,
    base: { service: 'openresidency' },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: { level: (label) => ({ level: label }) },
    redact: { paths: [...REDACT_PATHS], censor: '[REDACTED]' },
  };
  const log = opts.destination ? pino(options, opts.destination) : pino(options);
  if (level !== requested) {
    log.warn({ requested }, `LOG_LEVEL "${requested}" is not a level; using "info"`);
  }
  return log;
}
