// SPDX-License-Identifier: Apache-2.0
/**
 * An authenticating shim that sits in front of the VC-API for the W3C test suite.
 *
 * WHY THIS EXISTS. The suite's own `post()` helper honours the headers configured in
 * `localConfig.cjs` only when the target URL is `https:`. On plain `http:` it hand-rolls
 * the request with a fixed header set and drops `Authorization`. Since the documented way
 * to run the suite is against `http://localhost:3000`, every request arrived unauthenticated
 * and the whole suite failed with `401 Operator authentication required` -- which reads as
 * dozens of conformance failures and is nothing of the kind.
 *
 * The alternative fixes are both worse. Opening the VC-API up would turn a government
 * issuer's DID into an unauthenticated signing oracle, which is the one thing
 * `test/w3c/README.md` says we will not do to pass a test. Patching the cloned suite would
 * be silently undone by the next `git clone` in `scripts/run-w3c-suite.sh`.
 *
 * So the guard stays exactly as it is in production, and the credential is added by a
 * process that already holds it. Local use only: it listens on the loopback interface and
 * is started and stopped by `scripts/run-w3c-suite.sh`.
 */
const http = require('node:http');

const TARGET_PORT = Number(process.env.W3C_PROXY_TARGET_PORT || 3000);
const TARGET_HOST = process.env.W3C_PROXY_TARGET_HOST || '127.0.0.1';
const LISTEN_PORT = Number(process.env.W3C_PROXY_PORT || 3100);
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!ADMIN_API_KEY) {
  console.error('auth-proxy: ADMIN_API_KEY is not set; the suite would fail with 401.');
  process.exit(1);
}

const server = http.createServer((clientReq, clientRes) => {
  const upstream = http.request(
    {
      host: TARGET_HOST,
      port: TARGET_PORT,
      path: clientReq.url,
      method: clientReq.method,
      headers: {
        ...clientReq.headers,
        host: `${TARGET_HOST}:${TARGET_PORT}`,
        authorization: `Bearer ${ADMIN_API_KEY}`,
      },
    },
    (upstreamRes) => {
      clientRes.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
      upstreamRes.pipe(clientRes);
    },
  );

  upstream.on('error', (err) => {
    clientRes.writeHead(502, { 'content-type': 'application/json' });
    clientRes.end(JSON.stringify({ errors: [`auth-proxy could not reach the server: ${err.message}`] }));
  });

  clientReq.pipe(upstream);
});

// Loopback only. This process holds an admin credential and adds it to whatever it is
// handed; it must not be reachable from anywhere but this machine.
server.listen(LISTEN_PORT, '127.0.0.1', () => {
  console.log(`auth-proxy: 127.0.0.1:${LISTEN_PORT} -> ${TARGET_HOST}:${TARGET_PORT}`);
});
