// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * OR-04 — the register answered every request with no security headers at all.
 *
 * This mounts the SAME middleware `main.ts` mounts, on a bare express app, and reads the
 * headers off a real response. It deliberately does not assert the spelling of the helmet
 * options: a test that checks the configuration object passes whether or not the
 * middleware was ever wired in, which is the failure mode worth excluding.
 *
 * It also pins the two properties of `/docs` that a CDN change could silently take away:
 * an exact pinned version, and an integrity hash on both tags.
 */
import express from 'express';
import type { AddressInfo } from 'node:net';
import { securityHeaders } from '../src/platform/security-headers';
import { docsPage } from '../src/meta/docs-page';

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

async function main(): Promise<void> {
  console.log('Security headers (OR-04)');

  const app = express();
  app.use(securityHeaders());
  app.get('/anything', (_req, res) => res.json({ ok: true }));
  app.get('/boom', (_req, res) => res.status(500).json({ ok: false }));

  const server = app.listen(0);
  await new Promise<void>((r) => server.once('listening', () => r()));
  const port = (server.address() as AddressInfo).port;

  const res = await fetch(`http://127.0.0.1:${port}/anything`);
  const h = res.headers;

  check('HSTS is set, one year, including subdomains',
    h.get('strict-transport-security') === 'max-age=31536000; includeSubDomains',
    h.get('strict-transport-security') ?? 'absent');
  check('X-Content-Type-Options: nosniff',
    h.get('x-content-type-options') === 'nosniff', h.get('x-content-type-options') ?? 'absent');
  check('Referrer-Policy is strict-origin-when-cross-origin',
    h.get('referrer-policy') === 'strict-origin-when-cross-origin',
    h.get('referrer-policy') ?? 'absent');

  const csp = h.get('content-security-policy') ?? '';
  check('CSP is present', csp.length > 0, 'absent');
  check("CSP default-src is 'self'", csp.includes("default-src 'self'"), csp);
  check("CSP forbids framing outright", csp.includes("frame-ancestors 'none'"), csp);
  check("CSP forbids plugins", csp.includes("object-src 'none'"), csp);

  // The directive most worth keeping strict: nothing in this service needs inline script,
  // and 'unsafe-inline' here would quietly undo most of the policy.
  const scriptSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src')) ?? '';
  check("script-src carries no 'unsafe-inline'", !scriptSrc.includes("'unsafe-inline'"), scriptSrc);
  check("script-src carries no 'unsafe-eval'", !scriptSrc.includes("'unsafe-eval'"), scriptSrc);
  check('jsdelivr is allowed for scripts, and only jsdelivr',
    scriptSrc.includes('https://cdn.jsdelivr.net') &&
      !/https:\/\/(?!cdn\.jsdelivr\.net)/.test(scriptSrc), scriptSrc);

  // A 5xx is the response an attacker can most easily provoke; headers must survive it.
  const errRes = await fetch(`http://127.0.0.1:${port}/boom`);
  check('headers are present on a 500 as well as a 200',
    errRes.headers.get('x-content-type-options') === 'nosniff' &&
      (errRes.headers.get('content-security-policy') ?? '').length > 0,
    `status ${errRes.status}`);

  await new Promise<void>((r) => server.close(() => r()));

  // /docs — the CDN assets must be pinned AND integrity-checked. A floating version and
  // an SRI hash cannot both be right, so the two are asserted together.
  const html = docsPage();
  check('docs pins an exact Swagger UI version, not a floating major',
    /swagger-ui-dist@\d+\.\d+\.\d+\//.test(html) && !/swagger-ui-dist@\d+\//.test(html),
    html.match(/swagger-ui-dist@[^/]+/)?.[0] ?? 'no reference');
  check('both CDN tags carry an SRI hash',
    (html.match(/integrity="sha384-/g) ?? []).length === 2,
    `${(html.match(/integrity="sha384-/g) ?? []).length} integrity attributes`);
  check('both CDN tags are crossorigin, without which SRI is not enforced',
    (html.match(/crossorigin="anonymous"/g) ?? []).length === 2,
    `${(html.match(/crossorigin="anonymous"/g) ?? []).length} crossorigin attributes`);

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

void main();
