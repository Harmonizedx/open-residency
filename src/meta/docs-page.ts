// SPDX-License-Identifier: Apache-2.0
/**
 * The browsable API docs page, kept out of the controller so it can be asserted without
 * a Nest container — `scripts/security-headers-smoke.ts` builds the HTML directly.
 *
 * ## What was wrong here (OR-04)
 *
 * The page loaded Swagger UI from `cdn.jsdelivr.net` at a floating major (`@5`), with no
 * integrity check. That is third-party script executing on the register's own origin,
 * changing whenever the CDN published a release, with nothing able to detect a
 * substitution. For a government residency register that is the more serious half of the
 * finding, and the review did not raise it.
 *
 * Now pinned to an exact version with SRI, so a CDN serving different bytes is refused by
 * the browser instead of executed.
 *
 * ⚠️ Bump `SWAGGER_VERSION` and BOTH hashes together, never one alone — a floating
 * version and an integrity hash cannot both be right, and a stale hash fails CLOSED.
 * Regenerate with:
 *   curl -sfL https://cdn.jsdelivr.net/npm/swagger-ui-dist@<v>/swagger-ui.css \
 *     | openssl dgst -sha384 -binary | openssl base64 -A
 */
const SWAGGER_VERSION = '5.34.0';

const SWAGGER_CSS = {
  url: `https://cdn.jsdelivr.net/npm/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui.css`,
  sri: 'sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF',
} as const;

const SWAGGER_JS = {
  url: `https://cdn.jsdelivr.net/npm/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui-bundle.js`,
  sri: 'sha384-9Td7MKiIr2S83E1kZyyVi8KdJw/S8CpAvu0llLyMeg0xq/hDGiZJfVn0fV4llCmK',
} as const;

/** `crossorigin` is required: without it the browser does not enforce `integrity`. */
export function docsPage(): string {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenResidency API</title>
<link rel="stylesheet" href="${SWAGGER_CSS.url}" integrity="${SWAGGER_CSS.sri}" crossorigin="anonymous">
</head><body>
<div id="swagger"></div>
<script src="${SWAGGER_JS.url}" integrity="${SWAGGER_JS.sri}" crossorigin="anonymous"></script>
<script>
  window.onload = () => SwaggerUIBundle({ url: '/openapi.yaml', dom_id: '#swagger' });
</script>
</body></html>`;
}
