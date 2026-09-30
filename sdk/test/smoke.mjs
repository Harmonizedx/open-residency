// SPDX-License-Identifier: Apache-2.0
/**
 * Runs the built client against a recording fetch: the right URL, method, headers and
 * body leave for each kind of call, and errors carry the status and parsed body.
 * No server is involved; `npm run build` first.
 */
import assert from 'node:assert/strict';
import { OpenResidencyClient, OpenResidencyError } from '../dist/index.js';

const calls = [];
function fakeFetch(reply = { status: 200, body: { ok: true } }) {
  return async (url, init) => {
    calls.push({ url, ...init });
    const text = reply.body === undefined ? '' : typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body);
    return new Response(text, {
      status: reply.status,
      headers: { 'content-type': reply.contentType ?? 'application/json' },
    });
  };
}
const last = () => calls[calls.length - 1];

// Named method: path parameter encoded, operator key sent, body serialised.
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov/', operatorKey: 'ork_x', fetch: fakeFetch() });
  await c.transitionRelationship('KT/1', { status: 'SUSPENDED', reason: 'review' });
  assert.equal(last().url, 'https://id.example.gov/residency/KT%2F1/relationship/transition');
  assert.equal(last().method, 'POST');
  assert.equal(last().headers['x-operator-key'], 'ork_x');
  assert.equal(last().headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(last().body), { status: 'SUSPENDED', reason: 'review' });
}

// Generic request: query string built, undefined values skipped, GET has no body.
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', operatorKey: 'ork_x', fetch: fakeFetch() });
  await c.request('get', '/admin/residents', { query: { countryCode: 'NG', limit: 50, offset: undefined } });
  assert.equal(last().url, 'https://id.example.gov/admin/residents?countryCode=NG&limit=50');
  assert.equal(last().method, 'GET');
  assert.equal(last().body, undefined);
}

// 'operator' auth with nothing configured fails before any request leaves.
{
  const before = calls.length;
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', fetch: fakeFetch() });
  await assert.rejects(() => c.me(), /requires operator authentication/);
  assert.equal(calls.length, before);
}

// 'auto' auth sends nothing when nothing is configured, and 'none' sends nothing when it is.
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', fetch: fakeFetch() });
  await c.residencyStatus('KT-1');
  assert.equal(last().headers['x-operator-key'], undefined);
  assert.equal(last().headers['authorization'], undefined);
  const d = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', operatorKey: 'ork_x', fetch: fakeFetch() });
  await d.countries();
  assert.equal(last().headers['x-operator-key'], undefined);
}

// Per-call bearer (the OpenID4VCI access token) and per-call headers (the USSD secret).
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', operatorKey: 'ork_x', fetch: fakeFetch() });
  await c.walletCredential('tok', { credential_configuration_id: 'residency' });
  assert.equal(last().headers['authorization'], 'Bearer tok');
  assert.equal(last().headers['x-operator-key'], undefined);
  await c.ussd({ text: '', phoneNumber: '+2348000000000' }, 'shh');
  assert.equal(last().headers['x-ussd-secret'], 'shh');
}

// Credential preference: operator key, then SSO token, then the legacy shared key.
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', adminKey: 'legacy', operatorToken: 'jwt', fetch: fakeFetch() });
  await c.verifyAuditChain();
  assert.equal(last().headers['authorization'], 'Bearer jwt');
  assert.equal(last().headers['x-admin-key'], undefined);
}

// Non-JSON bodies come back as text.
{
  const c = new OpenResidencyClient({
    baseUrl: 'https://id.example.gov',
    operatorKey: 'ork_x',
    fetch: fakeFetch({ status: 200, body: 'a,b\r\n1,2\r\n', contentType: 'text/csv; charset=utf-8' }),
  });
  const csv = await c.statisticsCsv();
  assert.equal(csv, 'a,b\r\n1,2\r\n');
  assert.equal(last().headers['accept'], 'text/csv');
}

// Errors carry the status and the parsed body.
{
  const c = new OpenResidencyClient({
    baseUrl: 'https://id.example.gov',
    fetch: fakeFetch({ status: 404, body: { statusCode: 404, message: 'Unknown residentId' } }),
  });
  await assert.rejects(
    () => c.residencyStatus('nope'),
    (e) => e instanceof OpenResidencyError && e.status === 404 && e.body.message === 'Unknown residentId',
  );
}

// A missing path parameter is a caller error, not a request to a wrong URL.
{
  const c = new OpenResidencyClient({ baseUrl: 'https://id.example.gov', fetch: fakeFetch() });
  await assert.rejects(() => c.request('get', '/residency/{residentId}', { path: {} }), /Missing path parameter "residentId"/);
}

console.log(`sdk smoke: ${calls.length} requests recorded, all assertions passed`);
