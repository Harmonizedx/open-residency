// SPDX-License-Identifier: Apache-2.0
import helmet from 'helmet';
import type { RequestHandler } from 'express';

/**
 * Security response headers for the whole API (OR-04).
 *
 * The register served none: no HSTS, no `nosniff`, no frame protection, no referrer
 * policy. Every route, including the privileged operator surface, answered with nothing
 * but `Content-Type` and the body.
 *
 * ## Why the CSP is written out instead of taking helmet's default
 *
 * Two reasons, and the second is the real one.
 *
 * helmet's default policy is aimed at a page-serving app, and this is predominantly a
 * JSON API — `frame-ancestors 'none'` and a tight `connect-src` matter here, `upgrade-
 * insecure-requests` does not, and the defaults drift between major versions.
 *
 * More importantly: `/docs` loads Swagger UI from jsdelivr, so that origin has to be
 * allowed somewhere. Written out, the allowance appears exactly once, next to the comment
 * explaining it, where a reviewer asking "what third-party code can run here?" will find
 * it. Inherited from a default and silently extended, it would not.
 *
 * The allowance is narrow by construction: `script-src` names jsdelivr and nothing else,
 * and the tags in `meta.controller.ts` carry SRI hashes against a pinned version, so a CDN
 * serving different bytes is refused by the browser rather than executed.
 *
 * ## What is deliberately NOT set
 *
 * `crossOriginEmbedderPolicy` is off. It requires COEP/CORP on every embedded resource,
 * buys nothing for a JSON API, and would break the docs page — a header that forces a
 * workaround is worse than no header.
 *
 * `'unsafe-inline'` is present for `style-src` only, because Swagger UI injects inline
 * styles. It is NOT present for `script-src`: nothing in this service needs inline script,
 * and that is the directive worth keeping strict.
 */
export function securityHeaders(): RequestHandler {
  return helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
        'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  });
}
