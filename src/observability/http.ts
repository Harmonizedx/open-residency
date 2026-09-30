// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { Logger } from 'pino';
import { elapsedMs, observeHttpRequest } from './metrics';

/**
 * One line and one histogram observation per request, with a request id to tie them to
 * anything else that happened while serving it.
 *
 * What is recorded: method, route PATTERN, status, duration, request id. What is not: the URL
 * (its query string can carry an identifier), the body (on two routes it IS the identifier),
 * any header (one of them is the operator's key). Bounding the log to what is safe is done
 * here by omission, and the redaction in `logging.ts` is the backstop for everything else.
 */

export const REQUEST_ID_HEADER = 'x-request-id';
const REQUEST_ID_SHAPE = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * Honour a well-formed inbound id -- the ingress usually sets one -- so a request can be
 * followed from the edge into this service; mint one otherwise. A malformed value is replaced,
 * not trimmed: it is caller-controlled text on its way into a log line.
 */
export function requestIdFrom(header: unknown): string {
  const value = Array.isArray(header) ? header[0] : header;
  return typeof value === 'string' && REQUEST_ID_SHAPE.test(value) ? value : randomUUID();
}

/** Paths mounted as whole sub-applications, which Express cannot resolve to a route pattern. */
const MOUNTED_PREFIXES = ['/oidc', '/app', '/.well-known'];

/**
 * A label with a small, fixed set of values. The matched route's pattern
 * (`/residency/:residentId`) when there is one; a mount prefix for the OIDC provider and the
 * static UI; `unmatched` for everything else, so a scan of random paths produces one series,
 * not one per path.
 */
export function routeLabel(
  req: Pick<Request, 'baseUrl' | 'originalUrl'> & { route?: { path?: unknown } },
): string {
  const pattern = req.route?.path;
  if (typeof pattern === 'string') return `${req.baseUrl ?? ''}${pattern}`;
  const path = (req.originalUrl ?? '').split('?')[0];
  for (const prefix of MOUNTED_PREFIXES) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return `${prefix}/*`;
  }
  return 'unmatched';
}

export type RequestWithId = Request & { id?: string };

/**
 * Express middleware. Installed before the body parsers so a request the parser rejects is
 * still counted and still carries an id. Probe traffic (`/health/*`) is logged at debug: a
 * kubelet asking every ten seconds would otherwise be most of the log.
 */
export function requestObserver(log: Logger) {
  return function observe(req: Request, res: Response, next: NextFunction): void {
    const started = process.hrtime.bigint();
    const reqId = requestIdFrom(req.headers[REQUEST_ID_HEADER]);
    (req as RequestWithId).id = reqId;
    res.setHeader(REQUEST_ID_HEADER, reqId);

    res.once('finish', () => {
      const durationMs = elapsedMs(started);
      const route = routeLabel(req);
      const status = res.statusCode;
      observeHttpRequest({ method: req.method, route, status, durationMs });

      const entry = {
        reqId,
        method: req.method,
        route,
        status,
        durationMs: Math.round(durationMs * 1000) / 1000,
      };
      if (route.startsWith('/health/')) log.debug(entry, 'request');
      else if (status >= 500) log.error(entry, 'request');
      else log.info(entry, 'request');
    });

    next();
  };
}
