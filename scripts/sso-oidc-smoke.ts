/* eslint-disable no-console */
/**
 * End-to-end OIDC flow test: boots the REAL oidc-provider from
 * buildOidcConfiguration and drives a full Authorization Code + PKCE sign-in through
 * HTTP, completing the login and consent interactions exactly as InteractionController
 * does, then exchanging the code for tokens and verifying the id_token.
 *
 * This is the gap the other suites left: `smoke:sso` exercises the authentication
 * *logic* (SsoAuthService) one layer below the HTTP surface, but nothing booted the
 * provider or walked a real code flow. This does -- so `buildOidcConfiguration` (clients,
 * claims, the published JWKS, the pairwise-subject derivation) and the interaction
 * completion are now observed working, not merely wired.
 *
 * It is hermetic: an in-memory store and a locally generated OIDC key, no database and
 * no network. It stands up a stub PlatformService exposing only the four members the
 * provider config reads -- the real PlatformService wiring is covered by the unit-level
 * suites; what is new here is the provider actually running.
 */
import { createServer, Server, IncomingMessage } from 'node:http';
import { request as httpRequest } from 'node:http';
import { AddressInfo } from 'node:net';
import type { Request, Response } from 'express';
import type Provider from 'oidc-provider';
import ProviderCtor from 'oidc-provider';
import { createLocalJWKSet, jwtVerify, exportJWK, generateKeyPair, JWK } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import { buildOidcConfiguration } from '../src/sso/oidc.provider';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { pairwiseSubject } from '../src/core/sso/pairwise';

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

const PEPPER = 'oidc-e2e-test-pepper';
const RESIDENT_ID = 'KT-7F3A-9K2P';
const CLIENT_ID = 'health';
const CLIENT_SECRET = 'health-client-secret-for-tests';
const REDIRECT_URI = 'https://health.katsina.example/callback';

const CONFIG: CountryConfig = parseCountryConfig({
  countryCode: 'NG',
  countryName: 'Nigeria',
  foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
  residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
  credential: {
    issuerDid: 'did:web:id.katsina.gov.ng',
    issuerName: 'Katsina State Residency Authority',
    type: 'StateResidencyCredential',
    validityDays: 1095,
    context: ['https://www.w3.org/ns/credentials/v2'],
  },
  subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  oidc: {
    subjectType: 'pairwise',
    relyingParties: [
      {
        clientId: CLIENT_ID,
        name: 'Katsina Health Service',
        sector: 'health',
        scopes: ['profile', 'residency'],
        redirectUris: [REDIRECT_URI],
      },
    ],
  },
});

/** The one resident this flow signs in. */
const RESIDENT_RECORD = {
  residentId: RESIDENT_ID,
  subjectRef: 'subject-ref-1',
  countryCode: 'NG',
  subnationalUnit: 'KT',
  assuranceLevel: 'verified',
  provisional: false,
  person: { fullName: 'Amina Bello', givenName: 'Amina', familyName: 'Bello' },
};

/** A stub PlatformService exposing exactly the members buildOidcConfiguration reads. */
function stubPlatform(oidcJwk: JWK): any {
  return {
    listConfigs: () => [CONFIG],
    getSubjectPepper: () => PEPPER,
    oidcSigningJwk: async () => oidcJwk,
    getStore: () => ({
      findByResidentId: async (id: string) => (id === RESIDENT_ID ? RESIDENT_RECORD : null),
    }),
  };
}

// --------------------------------------------------------------------------
// A tiny HTTP client with a cookie jar and manual redirect control, because
// node:fetch hides Location on manual redirects and follows them otherwise.
// --------------------------------------------------------------------------

interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  location?: string;
}

class CookieJar {
  private jar = new Map<string, string>();

  store(res: IncomingMessage) {
    const set = res.headers['set-cookie'] ?? [];
    for (const line of set) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      // An empty value with an expiry in the past is a deletion.
      if (value === '') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  header(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

function req(
  method: string,
  url: string,
  jar: CookieJar,
  opts: { headers?: Record<string, string>; body?: string } = {},
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const headers: Record<string, string> = { ...opts.headers };
    const cookie = jar.header();
    if (cookie) headers.cookie = cookie;
    if (opts.body) {
      headers['content-length'] = String(Buffer.byteLength(opts.body));
      headers['content-type'] = headers['content-type'] ?? 'application/x-www-form-urlencoded';
    }

    const r = httpRequest(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers },
      (res) => {
        jar.store(res);
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            location: res.headers.location,
          }),
        );
      },
    );
    r.on('error', reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}

/**
 * Follow redirects until the response is not a redirect, or until it points at the
 * relying party's redirect_uri (the end of the flow). Interaction routes complete
 * themselves server-side and then redirect on, so the client only has to keep following.
 */
async function followUntilRedirectUri(
  start: HttpResponse,
  base: string,
  jar: CookieJar,
): Promise<HttpResponse> {
  let res = start;
  let hops = 0;
  while (res.location && hops++ < 12) {
    if (process.env.DEBUG_OIDC) console.error(`  [hop ${hops}] ${res.status} -> ${res.location}`);
    const next = new URL(res.location, base).toString();
    if (next.startsWith(REDIRECT_URI)) return res; // stop at the RP callback
    res = await req('GET', next, jar);
  }
  if (process.env.DEBUG_OIDC) {
    console.error(`  [final] ${res.status} loc=${res.location ?? ''} body=${res.body.slice(0, 300)}`);
  }
  return res;
}

const b64url = (b: Buffer): string =>
  b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function main() {
  console.log('\n== OpenResidency SSO/OIDC end-to-end flow ==\n');

  // Secrets the provider config demands, or it refuses to build (by design).
  process.env.HEALTH_CLIENT_SECRET = CLIENT_SECRET;
  process.env.OIDC_COOKIE_SECRET = 'oidc-cookie-secret-for-tests-0123456789';

  // A real Ed25519 OIDC signing key, generated locally.
  const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const oidcJwk: JWK = { ...(await exportJWK(kp.privateKey)), kid: 'oidc-key-1', alg: 'EdDSA', use: 'sig' };

  const config = await buildOidcConfiguration(stubPlatform(oidcJwk));
  check('buildOidcConfiguration produced a config', !!config);
  check('it registered the relying party as a client', (config.clients as unknown[]).length === 1);
  check('the published JWKS carries the OIDC signing key', (config.jwks as any).keys[0].kid === 'oidc-key-1');
  check('the JWKS exposes only the PUBLIC key (no private d)', !('d' in (config.jwks as any).keys[0]));

  // Boot the provider and mount it plus an interaction handler that mirrors
  // InteractionController: complete login, then consent.
  const issuer = 'http://127.0.0.1:%PORT%/oidc';
  let provider!: Provider;
  const server: Server = createServer(async (rawReq, rawRes) => {
    const url = new URL(rawReq.url ?? '/', `http://${rawReq.headers.host}`);

    // Interaction routes: /interaction/:uid  (login and consent, auto-completed).
    if (url.pathname.startsWith('/interaction/')) {
      try {
        const details = await provider.interactionDetails(rawReq as Request, rawRes as Response);
        const { prompt, params } = details;
        if (prompt.name === 'login') {
          const redirectTo = await provider.interactionResult(
            rawReq as Request,
            rawRes as Response,
            { login: { accountId: RESIDENT_ID } },
            { mergeWithLastSubmission: false },
          );
          rawRes.writeHead(303, { location: redirectTo });
          rawRes.end();
          return;
        }
        if (prompt.name === 'consent') {
          const grant = new provider.Grant({ accountId: RESIDENT_ID, clientId: String(params.client_id) });
          grant.addOIDCScope(String(params.scope ?? 'openid'));
          const grantId = await grant.save();
          const redirectTo = await provider.interactionResult(
            rawReq as Request,
            rawRes as Response,
            { consent: { grantId } },
            { mergeWithLastSubmission: true },
          );
          rawRes.writeHead(303, { location: redirectTo });
          rawRes.end();
          return;
        }
        rawRes.writeHead(400);
        rawRes.end('unknown prompt');
      } catch (e) {
        rawRes.writeHead(500);
        rawRes.end(String((e as Error).message));
      }
      return;
    }

    // Everything under /oidc → the provider.
    if (url.pathname === '/oidc' || url.pathname.startsWith('/oidc/')) {
      rawReq.url = rawReq.url!.replace(/^\/oidc/, '') || '/';
      return (provider.callback() as any)(rawReq, rawRes);
    }
    rawRes.writeHead(404);
    rawRes.end();
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  provider = new ProviderCtor(`${base}/oidc`, config);
  provider.proxy = true;

  // --- Drive a real Authorization Code + PKCE flow --------------------------
  const jar = new CookieJar();
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(8));

  const authUrl =
    `${base}/oidc/auth?client_id=${CLIENT_ID}` +
    `&response_type=code&scope=${encodeURIComponent('openid profile residency health')}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`;

  const authStart = await req('GET', authUrl, jar);
  if (process.env.DEBUG_OIDC) console.error("[authStart] " + authStart.status + " " + authStart.body.replace(/<[^>]+>/g," ").replace(/\s+/g," ").replace(/^.*error_description/,"error_description").slice(0,300));
  const ended = await followUntilRedirectUri(authStart, base, jar);

  check('the flow ends by redirecting to the RP callback', (ended.location ?? '').startsWith(REDIRECT_URI));
  const cbUrl = new URL(ended.location ?? '');
  const code = cbUrl.searchParams.get('code');
  check('an authorization code is returned', !!code);
  check('the state parameter round-trips (CSRF binding)', cbUrl.searchParams.get('state') === state);

  // --- Exchange the code for tokens -----------------------------------------
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const tokenRes = await req('POST', `${base}/oidc/token`, jar, {
    headers: { authorization: `Basic ${basic}` },
    body:
      `grant_type=authorization_code&code=${code}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_verifier=${verifier}`,
  });
  check('the token endpoint returns 200', tokenRes.status === 200, `status ${tokenRes.status}: ${tokenRes.body.slice(0, 200)}`);
  const tokens = JSON.parse(tokenRes.body || '{}');
  check('an id_token is issued', typeof tokens.id_token === 'string');
  check('an access_token is issued', typeof tokens.access_token === 'string');

  // --- PKCE is actually enforced: a wrong verifier must be rejected ---------
  // (Fresh code; the one above is spent. Re-run the front channel.)
  const jar2 = new CookieJar();
  const verifier2 = b64url(randomBytes(32));
  const challenge2 = b64url(createHash('sha256').update(verifier2).digest());
  const auth2 = await req(
    'GET',
    `${base}/oidc/auth?client_id=${CLIENT_ID}&response_type=code` +
      `&scope=${encodeURIComponent('openid profile')}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      `&code_challenge=${challenge2}&code_challenge_method=S256&state=x`,
    jar2,
  );
  const ended2 = await followUntilRedirectUri(auth2, base, jar2);
  const code2 = new URL(ended2.location ?? '').searchParams.get('code');
  const badExchange = await req('POST', `${base}/oidc/token`, jar2, {
    headers: { authorization: `Basic ${basic}` },
    body:
      `grant_type=authorization_code&code=${code2}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_verifier=${b64url(randomBytes(32))}`,
  });
  check('a wrong PKCE verifier is rejected (400)', badExchange.status === 400);

  // --- Verify the id_token against the PUBLISHED JWKS -----------------------
  const discovery = await req('GET', `${base}/oidc/.well-known/openid-configuration`, jar);
  const meta = JSON.parse(discovery.body);
  check('discovery advertises the jwks_uri', typeof meta.jwks_uri === 'string');
  const jwksRes = await req('GET', meta.jwks_uri, jar);
  const jwks = createLocalJWKSet(JSON.parse(jwksRes.body));

  let payload: any;
  try {
    const verified = await jwtVerify(tokens.id_token, jwks, {
      issuer: `${base}/oidc`,
      audience: CLIENT_ID,
    });
    payload = verified.payload;
  } catch (e) {
    payload = null;
    check('the id_token verifies against the published JWKS', false, (e as Error).message);
  }
  if (payload) {
    check('the id_token verifies against the published JWKS', true);
    const expectedSub = pairwiseSubject(PEPPER, CLIENT_ID, RESIDENT_ID);
    check('the sub is the PAIRWISE subject, not the residency id', payload.sub === expectedSub);
    check('the sub is NOT the raw residency id (no cross-service correlation)', payload.sub !== RESIDENT_ID);
    check('the id_token audience is the relying party', payload.aud === CLIENT_ID);
  }

  // --- Userinfo returns the consented claims --------------------------------
  const userinfo = await req('GET', `${base}/oidc/me`, jar, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  check('userinfo returns 200 with the access token', userinfo.status === 200, `status ${userinfo.status}`);
  const claims = JSON.parse(userinfo.body || '{}');
  check('userinfo releases the consented residency claim', claims.resident_id === RESIDENT_ID);
  check('userinfo sub matches the id_token sub (consistent pairwise id)', claims.sub === payload?.sub);

  server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
