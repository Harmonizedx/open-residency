/* eslint-disable no-console */
/**
 * Bring-your-own biometric authority: the config-driven HTTP matcher and its two
 * load-bearing properties.
 *
 * The matcher lets a deployment point at whatever attests biometric matches for its
 * jurisdiction (a national ABIS, a MOSIP gateway, a vendor SDK behind an HTTP shim),
 * exactly as `foundational` and `messaging` are bring-your-own. This drives it against a
 * mock authority and proves the two things that make it more than a config copy of the
 * messaging provider:
 *
 *   FAIL-CLOSED. A network error, timeout, non-2xx, or unexpected response body must all
 *   resolve to a NON-match with a reason -- never a pass. At AAL3 a false positive is
 *   account takeover, so "could not confirm" and "confirmed" must be impossible to confuse.
 *
 *   CAPTURE PRIVACY. The live sample is sent only to the authority. It is never returned in
 *   the result, so it cannot leak into logs or the audit trail through the match result.
 *
 * Plus the assurance consequence: a passkey possession factor combined with an attested
 * match composes to AAL3.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { buildBiometricMatcher, BiometricHttpConfig } from '../src/core/proofing/biometric';
import { assess } from '../src/core/sso/assurance';
import { parseCountryConfig } from '../src/core/config/country-config';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
}

interface Mock {
  server: Server;
  baseUrl: string;
  /** What the authority attests for the next call. */
  verdict: 'match' | 'nomatch' | 'error' | 'hang' | 'garbage';
  /** Everything the authority received -- so the test can prove what was (not) sent. */
  received: { path?: string; body?: any; auth?: string }[];
}

async function startMock(): Promise<Mock> {
  const state: Mock = { server: undefined as unknown as Server, baseUrl: '', verdict: 'match', received: [] };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined;
      state.received.push({ path: req.url, body, auth: req.headers.authorization });
      if (state.verdict === 'hang') return; // never respond -> client must time out
      if (state.verdict === 'error') {
        res.writeHead(503);
        res.end('unavailable');
        return;
      }
      if (state.verdict === 'garbage') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('not json');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          result: { matched: state.verdict === 'match', score: state.verdict === 'match' ? 0.98 : 0.1, authority: 'nat-abis' },
        }),
      );
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  state.server = server;
  state.baseUrl = `http://127.0.0.1:${port}`;
  return state;
}

function cfg(baseUrl: string): BiometricHttpConfig {
  return {
    provider: 'GENERIC_HTTP',
    baseUrl,
    timeoutMs: 500,
    source: 'configured-fallback',
    request: {
      method: 'POST',
      path: '/verify/{residentId}',
      bodyTemplate: { residentId: '{residentId}', modality: '{modality}', probe: '{sample}' },
      matchedFlag: { path: 'result.matched', equals: true },
      scorePath: 'result.score',
      sourcePath: 'result.authority',
    },
  };
}

async function main() {
  console.log('\n== Bring-your-own biometric authority (config-driven, fail-closed) ==\n');
  const mock = await startMock();
  const matcher = buildBiometricMatcher(cfg(mock.baseUrl))!;
  const capture = { residentId: 'KT-7F3A-9K2P', modality: 'face' as const, sample: 'LIVE-PROBE-SECRET' };

  // --- Config parsing: the block is accepted on a real country config -------
  const parsed = parseCountryConfig({
    countryCode: 'NG', countryName: 'Nigeria',
    foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: { issuerDid: 'did:web:x', issuerName: 'X', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
    biometric: cfg(mock.baseUrl),
  });
  check('a biometric block parses on a country config', parsed.biometric.provider === 'GENERIC_HTTP');
  check('provider defaults to NONE when the block is omitted', parseCountryConfig({
    countryCode: 'NG', countryName: 'Nigeria',
    foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: { issuerDid: 'did:web:x', issuerName: 'X', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  }).biometric.provider === 'NONE');
  check('NONE yields no matcher (deployment offers no step-up)', buildBiometricMatcher({ provider: 'NONE' }) === null);

  // --- The happy path: an authority attests a match -------------------------
  mock.verdict = 'match';
  const good = await matcher.match(capture);
  check('a match is attested (matched=true)', good.matched === true);
  check('the score is carried through', good.score === 0.98);
  check('the attesting authority from the response is recorded (for audit)', good.source === 'nat-abis');

  // --- CAPTURE PRIVACY ------------------------------------------------------
  const sent = mock.received.at(-1)!;
  check('the live capture is sent to the authority (in the request body)', sent.body?.probe === 'LIVE-PROBE-SECRET');
  check('the residentId is in the request path', sent.path === '/verify/KT-7F3A-9K2P');
  check(
    'the capture does NOT appear anywhere in the match RESULT (cannot leak to logs/audit)',
    !JSON.stringify(good).includes('LIVE-PROBE-SECRET'),
  );

  // --- FAIL-CLOSED: every failure mode is a non-match, never a pass ---------
  mock.verdict = 'nomatch';
  const no = await matcher.match(capture);
  check('a genuine non-match is matched=false with NO_MATCH', no.matched === false && no.reason === 'NO_MATCH');

  mock.verdict = 'error';
  const err = await matcher.match(capture);
  check('a 5xx from the authority fails CLOSED (not a pass)', err.matched === false && err.reason === 'HTTP_503');

  mock.verdict = 'garbage';
  const garbage = await matcher.match(capture);
  check('a non-JSON / unexpected body fails CLOSED', garbage.matched === false);

  mock.verdict = 'hang';
  const timedOut = await matcher.match(capture);
  check('a hung authority times out and fails CLOSED (TIMEOUT)', timedOut.matched === false && timedOut.reason === 'TIMEOUT');

  // A matcher pointed at an unreachable host fails closed, not throws.
  const dead = buildBiometricMatcher(cfg('http://127.0.0.1:1'))!;
  const unreachable = await dead.match(capture);
  check('an unreachable authority fails CLOSED (SERVICE_UNAVAILABLE), never throws', unreachable.matched === false && unreachable.reason === 'SERVICE_UNAVAILABLE');

  // Misconfiguration is refused at construction, not silently degraded.
  let refusedNoBase = false;
  try { buildBiometricMatcher({ provider: 'GENERIC_HTTP', request: { matchedFlag: { path: 'x' } } } as BiometricHttpConfig); } catch { refusedNoBase = true; }
  check('GENERIC_HTTP without a baseUrl is refused at construction', refusedNoBase);
  let refusedNoFlag = false;
  try { buildBiometricMatcher({ provider: 'GENERIC_HTTP', baseUrl: 'http://x' } as BiometricHttpConfig); } catch { refusedNoFlag = true; }
  check('GENERIC_HTTP without a matchedFlag is refused at construction', refusedNoFlag);

  // --- The assurance consequence: passkey + attested match = AAL3 -----------
  check('a passkey alone is AAL2', assess(['webauthn']).aal === 2);
  const stepUp = assess(good.matched ? ['webauthn', 'biometric'] : ['webauthn']);
  check('passkey + an attested match composes to AAL3', stepUp.aal === 3 && stepUp.acr === 'urn:openresidency:aal3');
  const downgraded = assess(no.matched ? ['webauthn', 'biometric'] : ['webauthn']);
  check('a passkey + a FAILED match does not reach AAL3', downgraded.aal === 2);

  // --- MOCK provider is dev-only --------------------------------------------
  const savedEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  let mockRefused = false;
  try { buildBiometricMatcher({ provider: 'MOCK' }); } catch { mockRefused = true; }
  process.env.NODE_ENV = savedEnv;
  check('the MOCK provider refuses to run in production', mockRefused);

  mock.server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
