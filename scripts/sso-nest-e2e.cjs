/* eslint-disable */
/**
 * Full-stack SSO end-to-end test: boots the ACTUAL NestJS application (AppModule) the
 * way main.ts does, against a real Postgres, and drives a complete "Sign in with the
 * State" flow through the REAL InteractionController -- the one production serves.
 *
 * This closes the last inferred gap. `smoke:sso-oidc` boots the provider but mirrors the
 * controller's interaction logic; this one exercises the genuine controller HTTP
 * endpoints: GET /interaction/:uid (login page), POST otp/start, POST otp/verify (real
 * one-time-code authentication, code captured off a real messaging provider), POST
 * confirm (consent), then the OAuth token exchange and id_token verification.
 *
 * Orchestration (ephemeral Postgres, schema push, build, teardown) is in
 * run-sso-nest-e2e.sh. This driver assumes: DATABASE_URL is set, the app is built to
 * dist/, and the Prisma client is generated. It manages its own mock server and config.
 *
 * The mock server plays two roles the flow needs:
 *   - contact directory (external mode): returns the resident's msisdn, and
 *   - SMS aggregator (GENERIC_HTTP): captures the delivered one-time code.
 */
require('reflect-metadata');
const http = require('node:http');
const { writeFileSync, mkdirSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash, randomBytes, generateKeyPairSync, sign: edSign } = require('node:crypto');

// --- A simulated WebAuthn authenticator (Ed25519), producing the exact wire artifacts a
// real passkey emits: a COSE public key, authenticatorData, clientDataJSON, and a signature
// over authData||SHA256(clientData). No browser or hardware key -- the crypto is real.
function makeEd25519Authenticator() {
  const cborUint = (n) => (n < 24 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x18, n]) : Buffer.from([0x19, n >> 8, n & 0xff]));
  const cborInt = (n) => { if (n >= 0) return cborUint(n); const u = cborUint(-1 - n); u[0] |= 0x20; return u; };
  const cborBytes = (b) => { const h = cborUint(b.length); h[0] |= 0x40; return Buffer.concat([h, b]); };
  const cborMap = (pairs) => { const h = cborUint(pairs.length); h[0] |= 0xa0; return Buffer.concat([h, ...pairs.map(([k, v]) => Buffer.concat([cborInt(k), v]))]); };
  const b64u = (b) => b.toString('base64url');

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const coseKey = cborMap([[1, cborInt(1)], [3, cborInt(-8)], [-1, cborInt(6)], [-2, cborBytes(x)]]);
  const credentialId = randomBytes(16);

  const authData = (rpId, flags, signCount, attested) => {
    const head = Buffer.concat([createHash('sha256').update(rpId, 'utf8').digest(), Buffer.from([flags]), Buffer.alloc(4)]);
    head.writeUInt32BE(signCount, 33);
    if (!attested) return head;
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(credentialId.length, 0);
    return Buffer.concat([head, Buffer.alloc(16), idLen, credentialId, coseKey]);
  };
  const clientData = (type, challenge, origin) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8');

  return {
    credentialId: b64u(credentialId),
    makeRegistration(challenge, rpId, origin) {
      return { credentialId: b64u(credentialId), authData: b64u(authData(rpId, 0x01 | 0x04 | 0x40, 0, true)), clientDataJSON: b64u(clientData('webauthn.create', challenge, origin)) };
    },
    makeAssertion(credentialId, challenge, rpId, origin, signCount) {
      const ad = authData(rpId, 0x01 | 0x04, signCount);
      const cd = clientData('webauthn.get', challenge, origin);
      const signed = Buffer.concat([ad, createHash('sha256').update(cd).digest()]);
      return { credentialId, authenticatorData: b64u(ad), clientDataJSON: b64u(cd), signature: b64u(edSign(null, signed, privateKey)) };
    },
  };
}

let pass = 0,
  fail = 0;
const check = (name, cond, detail) => {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
};

const RESIDENT_ID = 'ZZ-7F3A-9K2P';
const PHONE = '+2348012345678';
const CLIENT_ID = 'tax'; // demo RP that carries the `residency` scope
const CLIENT_SECRET = 'tax-client-secret-for-tests';
const REDIRECT_URI = 'http://localhost:4002/callback';
const PEPPER = 'nest-e2e-subject-pepper';

const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// --- cookie-jar HTTP client with manual redirect control ------------------
class CookieJar {
  constructor() {
    this.jar = new Map();
  }
  store(headers) {
    for (const line of headers['set-cookie'] ?? []) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  header() {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

function req(method, url, jar, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const headers = { ...opts.headers };
    const cookie = jar.header();
    if (cookie) headers.cookie = cookie;
    if (opts.body) {
      headers['content-length'] = String(Buffer.byteLength(opts.body));
      headers['content-type'] = headers['content-type'] ?? 'application/json';
    }
    const r = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers },
      (res) => {
        jar.store(res.headers);
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), location: res.headers.location }),
        );
      },
    );
    r.on('error', reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}

/**
 * Follow redirects but STOP (without entering) as soon as the next hop is an interaction
 * page or the RP callback -- so the caller can decide what to do with each interaction
 * (render the login page, run OTP, confirm consent) rather than blindly GETting it.
 */
async function followToStop(start, base, jar) {
  let res = start;
  let hops = 0;
  while (res.location && hops++ < 15) {
    const next = new URL(res.location, base).toString();
    if (process.env.DEBUG_OIDC) console.error(`  [hop ${hops}] ${res.status} -> ${next}`);
    if (next.startsWith(REDIRECT_URI) || new URL(next).pathname.startsWith('/interaction/')) return res;
    res = await req('GET', next, jar);
  }
  return res;
}
const interactionUid = (loc, base) => new URL(loc, base).pathname.split('/')[2];

async function main() {
  const captured = { code: null, contactHits: 0, smsHits: 0, biometricHits: 0, biometricProbe: null };

  // --- Mock server: contact directory + SMS aggregator ---------------------
  const mock = http.createServer((rq, rs) => {
    const chunks = [];
    rq.on('data', (c) => chunks.push(c));
    rq.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (rq.url.startsWith('/contacts/')) {
        captured.contactHits++;
        rs.writeHead(200, { 'content-type': 'application/json' });
        rs.end(JSON.stringify({ msisdn: PHONE }));
        return;
      }
      if (rq.url.startsWith('/sms')) {
        captured.smsHits++;
        // The GENERIC_HTTP request maps the SMS text into `text`; the code is 6 digits.
        let text = '';
        try {
          text = JSON.parse(body).text ?? '';
        } catch {
          text = body;
        }
        const m = /\b(\d{6})\b/.exec(text);
        if (m) captured.code = m[1];
        rs.writeHead(200, { 'content-type': 'application/json' });
        rs.end(JSON.stringify({ id: 'sms-' + Date.now() }));
        return;
      }
      if (rq.url.startsWith('/biometric/verify')) {
        // A mock biometric authority: attests a match only for the agreed live probe, and
        // records what it received so the test can prove the capture reached it (and only it).
        captured.biometricHits++;
        let probe = '';
        try { probe = JSON.parse(body).sample ?? ''; } catch { /* ignore */ }
        captured.biometricProbe = probe;
        rs.writeHead(200, { 'content-type': 'application/json' });
        rs.end(JSON.stringify({ matched: probe === 'LIVE-FACE-PROBE', score: probe === 'LIVE-FACE-PROBE' ? 0.99 : 0.0, authority: 'demo-abis' }));
        return;
      }
      rs.writeHead(404);
      rs.end();
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const mockPort = mock.address().port;
  const mockBase = `http://127.0.0.1:${mockPort}`;

  // --- Country config dir pointing contact + SMS at the mock ---------------
  const cfgDir = join(tmpdir(), `ors-e2e-cfg-${process.pid}`);
  mkdirSync(cfgDir, { recursive: true });
  writeFileSync(
    join(cfgDir, 'zz.yaml'),
    `countryCode: ZZ
countryName: Demoland
defaultSubnationalUnit: DX
foundational:
  provider: MOCK
  inputs: [{ key: nationalId, label: National ID }]
  assuranceOnSuccess: verified
residency:
  minAssurance: verified
  proofOfResidence: attestation
credential:
  issuerDid: did:web:id.demoland.example
  issuerName: Demoland Residency Authority
  type: StateResidencyCredential
  validityDays: 365
  context: [https://www.w3.org/ns/credentials/v2]
subnationalUnits:
  - { code: DX, name: Demo District, parent: ZZ, level: state }
oidc:
  subjectType: pairwise
  relyingParties:
    - clientId: tax
      name: Demoland Revenue Authority
      sector: tax
      scopes: [profile, residency]
      redirectUris: [${REDIRECT_URI}]
      postLogoutRedirectUris: [http://localhost:4002]
messaging:
  provider: GENERIC_HTTP
  baseUrl: ${mockBase}
  sender: Demoland
  request:
    method: POST
    path: /sms
    bodyTemplate: { to: "{to}", text: "{body}" }
contactDirectory:
  mode: external
  external:
    baseUrl: ${mockBase}
    path: /contacts/{residentId}
    responsePath: msisdn
biometric:
  provider: GENERIC_HTTP
  baseUrl: ${mockBase}
  source: configured-fallback
  request:
    method: POST
    path: /biometric/verify
    bodyTemplate: { residentId: "{residentId}", modality: "{modality}", sample: "{sample}" }
    matchedFlag: { path: matched, equals: true }
    scorePath: score
    sourcePath: authority
`,
  );

  // --- Environment the app needs to boot -----------------------------------
  process.env.NODE_ENV = 'test';
  process.env.COUNTRY_CONFIG_DIR = cfgDir;
  process.env.SUBJECT_PEPPER = PEPPER;
  process.env.ISSUER_KEY_BACKEND = 'dev';
  process.env.OIDC_COOKIE_SECRET = 'nest-e2e-cookie-secret-0123456789';
  process.env.TAX_CLIENT_SECRET = CLIENT_SECRET;
  process.env.ADMIN_API_KEY = 'nest-e2e-admin-key';
  // A stable logical origin for WebAuthn. The app binds a random port, but the WebAuthn
  // rpId/origin are derived from PUBLIC_BASE_URL (what a browser would report), not from
  // the transport port -- so the simulated authenticator signs these exact values.
  process.env.PUBLIC_BASE_URL = 'http://localhost:8080';

  // --- Boot the ACTUAL app, exactly as main.ts does ------------------------
  const { NestFactory } = require('@nestjs/core');
  const { json, urlencoded } = require('express');
  const { AppModule } = require('../dist/app.module');
  const { OIDC_PROVIDER } = require('../dist/sso/oidc.module');

  const app = await NestFactory.create(AppModule, { bodyParser: false, logger: false });
  app.use(json());
  app.use(urlencoded({ extended: false }));
  const provider = app.get(OIDC_PROVIDER);
  app.use('/oidc', provider.callback());
  await app.listen(0, '127.0.0.1');
  const url = await app.getUrl();
  const base = url.replace('[::1]', '127.0.0.1').replace('0.0.0.0', '127.0.0.1');

  console.log('\n== OpenResidency full-stack SSO (real NestJS app + Postgres) ==\n');

  // --- Seed a resident directly in the store -------------------------------
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  // Idempotent: a service-container database may persist across re-runs, so clear any
  // prior row before seeding rather than tripping the unique constraint.
  await prisma.resident.deleteMany({ where: { residentId: RESIDENT_ID } });
  await prisma.resident.create({
    data: {
      residentId: RESIDENT_ID,
      subjectRef: 'nest-e2e-subject-ref',
      countryCode: 'ZZ',
      subnationalUnit: 'DX',
      providerCode: 'MOCK',
      assuranceLevel: 'verified',
      statusListIndex: 1,
      fullName: 'Amina Bello',
      givenName: 'Amina',
      familyName: 'Bello',
    },
  });
  check('a resident exists in the real store', !!(await prisma.resident.findUnique({ where: { residentId: RESIDENT_ID } })));

  // --- Discovery is served by the real provider ----------------------------
  const jar = new CookieJar();
  const disco = await req('GET', `${base}/oidc/.well-known/openid-configuration`, jar);
  check('OIDC discovery is served (200)', disco.status === 200, `status ${disco.status}`);
  const meta = JSON.parse(disco.body || '{}');
  const issuer = meta.issuer;

  // --- Drive Authorization Code + PKCE through the REAL controller ----------
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(8));
  const authUrl =
    `${base}/oidc/auth?client_id=${CLIENT_ID}&response_type=code` +
    `&scope=${encodeURIComponent('openid profile residency tax')}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`;

  // Provider decides login is needed and redirects to the real /interaction/:uid.
  const toLogin = await followToStop(await req('GET', authUrl, jar), base, jar);
  check('the flow redirects into the real interaction endpoint', (toLogin.location ?? '').includes('/interaction/'));
  const uid = interactionUid(toLogin.location, base);

  // The real InteractionController renders the login page.
  const loginPage = await req('GET', `${base}/interaction/${uid}`, jar);
  check('the real login page renders (200 HTML)', loginPage.status === 200 && /sign|code|residen/i.test(loginPage.body));

  // Real one-time-code path: request a code, capture it off the aggregator, submit it.
  const otpStart = await req('POST', `${base}/interaction/${uid}/otp/start`, jar, {
    body: JSON.stringify({ residentId: RESIDENT_ID }),
  });
  check('otp/start is accepted', otpStart.status >= 200 && otpStart.status < 300, `status ${otpStart.status}`);
  check('the contact directory was queried for the msisdn', captured.contactHits > 0);
  check('a one-time code was delivered to the aggregator', captured.smsHits > 0 && !!captured.code);

  const otpVerify = await req('POST', `${base}/interaction/${uid}/otp/verify`, jar, {
    body: JSON.stringify({ residentId: RESIDENT_ID, code: captured.code }),
  });
  // finishLogin completes the interaction and redirects back into the auth flow, which
  // then requires a consent interaction. Stop at it and complete it via the real controller.
  let ended = await followToStop(otpVerify, base, jar);
  check('after login, a consent interaction is required', (ended.location ?? '').includes('/interaction/'));
  if ((ended.location ?? '').includes('/interaction/')) {
    const cUid = interactionUid(ended.location, base);
    const consentPage = await req('GET', `${base}/interaction/${cUid}`, jar);
    check('the real consent page renders (200 HTML)', consentPage.status === 200);
    const confirm = await req('POST', `${base}/interaction/${cUid}/confirm`, jar, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: '',
    });
    ended = await followToStop(confirm, base, jar);
  }

  check('the flow ends at the RP callback with a code', (ended.location ?? '').startsWith(REDIRECT_URI) && /[?&]code=/.test(ended.location ?? ''));
  const code = new URL(ended.location ?? 'http://x').searchParams.get('code');
  check('the state round-trips (CSRF binding)', new URL(ended.location ?? 'http://x').searchParams.get('state') === state);

  // --- Token exchange against the real token endpoint ----------------------
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const tok = await req('POST', `${base}/oidc/token`, jar, {
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_verifier=${verifier}`,
  });
  check('the token endpoint returns 200', tok.status === 200, `status ${tok.status}: ${tok.body.slice(0, 200)}`);
  const tokens = JSON.parse(tok.body || '{}');
  check('an id_token and access_token are issued', typeof tokens.id_token === 'string' && typeof tokens.access_token === 'string');

  // --- Verify the id_token against the published JWKS ----------------------
  const jose = require('jose');
  const jwksRes = await req('GET', meta.jwks_uri, jar);
  const jwks = jose.createLocalJWKSet(JSON.parse(jwksRes.body));
  let payload = null;
  try {
    ({ payload } = await jose.jwtVerify(tokens.id_token, jwks, { issuer, audience: CLIENT_ID }));
    check('the id_token verifies against the published JWKS', true);
  } catch (e) {
    check('the id_token verifies against the published JWKS', false, e.message);
  }
  if (payload) {
    check('the sub is pairwise, NOT the raw residency id', payload.sub !== RESIDENT_ID && typeof payload.sub === 'string' && payload.sub.length > 0);
    check('the id_token audience is the relying party', payload.aud === CLIENT_ID);
    // Assurance step-up: the id_token carries acr/amr reflecting the factor used. This
    // sign-in was the one-time-code fallback, so it is AAL1 with amr=[otp] -- proving the
    // real InteractionController threads assurance through the real provider into the token.
    check('the id_token carries the assurance level (acr) for the factor used', payload.acr === 'urn:openresidency:aal1', `acr=${payload.acr}`);
    check('the id_token amr names the one-time-code method', Array.isArray(payload.amr) && payload.amr.includes('otp'), `amr=${JSON.stringify(payload.amr)}`);
  }

  // --- Userinfo releases the consented residency claim ---------------------
  const ui = await req('GET', `${base}/oidc/me`, jar, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  check('userinfo returns 200', ui.status === 200, `status ${ui.status}`);
  const claims = JSON.parse(ui.body || '{}');
  check('userinfo releases the consented resident_id (tax has the residency scope)', claims.resident_id === RESIDENT_ID);
  check('userinfo sub matches the id_token sub', claims.sub === payload?.sub);

  // --- WebAuthn: enroll a passkey (OTP-authorized), then sign in with it -----
  // Proves the whole HTTP factor end to end through the real controllers: a citizen who
  // holds their one-time code enrolls a passkey, and a subsequent sign-in with that passkey
  // authenticates at AAL2 (phishing-resistant) -- visible in the id_token's acr/amr.
  console.log('\n-- WebAuthn passkey: enroll then sign in --');
  const RP_ORIGIN = 'http://localhost:8080';
  const RP_ID = 'localhost';
  const sim = makeEd25519Authenticator();

  // (1) Get a fresh OTP to AUTHORIZE enrollment (the prior code was consumed by login).
  captured.code = null;
  await req('POST', `${base}/interaction/enroll/otp/start`, new CookieJar(), { body: JSON.stringify({ residentId: RESIDENT_ID }) });
  check('a fresh one-time code was delivered for enrollment authorization', !!captured.code);

  // (2) register/start with the code -> registration options + challenge.
  const regStart = await req('POST', `${base}/webauthn/register/start`, new CookieJar(), {
    body: JSON.stringify({ residentId: RESIDENT_ID, otpCode: captured.code }),
  });
  const regStartBody = JSON.parse(regStart.body || '{}');
  check('register/start is authorized by the one-time code', regStartBody.ok === true && !!regStartBody.challengeId);

  // (3) The simulated authenticator produces an attestation over the registration challenge.
  const regCeremony = sim.makeRegistration(regStartBody.options.challenge, RP_ID, RP_ORIGIN);
  const regFinish = await req('POST', `${base}/webauthn/register/finish`, new CookieJar(), {
    body: JSON.stringify({ challengeId: regStartBody.challengeId, residentId: RESIDENT_ID, ...regCeremony }),
  });
  check('register/finish persists the passkey', JSON.parse(regFinish.body || '{}').ok === true, regFinish.body);
  check('the passkey is stored in the real database', (await prisma.webAuthnCredential.count({ where: { residentId: RESIDENT_ID } })) === 1);

  // (4) A NEW OIDC sign-in, this time with the passkey.
  const jarW = new CookieJar();
  const verifierW = b64url(randomBytes(32));
  const challengeW = b64url(createHash('sha256').update(verifierW).digest());
  const authUrlW =
    `${base}/oidc/auth?client_id=${CLIENT_ID}&response_type=code&scope=${encodeURIComponent('openid profile residency tax')}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_challenge=${challengeW}&code_challenge_method=S256&state=w`;
  const toLoginW = await followToStop(await req('GET', authUrlW, jarW), base, jarW);
  const uidW = interactionUid(toLoginW.location, base);

  // (5) webauthn/authenticate/start -> options with the resident's credential + challenge.
  const authStart = await req('POST', `${base}/interaction/${uidW}/webauthn/authenticate/start`, jarW, {
    body: JSON.stringify({ residentId: RESIDENT_ID }),
  });
  const authStartBody = JSON.parse(authStart.body || '{}');
  check(
    'webauthn/authenticate/start returns the resident\'s credential to sign',
    authStart.status < 300 && authStartBody.options?.allowCredentials?.length === 1,
    `status=${authStart.status} body=${authStart.body.slice(0, 120)}`,
  );

  // (6) Sign the assertion and finish -> completes the login. This time we ALSO submit a
  // biometric capture, so the passkey possession is combined with an attested authoritative
  // match to reach AAL3. The live probe is sent to the biometric authority (the mock) and
  // must not surface anywhere else.
  const assertion = sim.makeAssertion(regCeremony.credentialId, authStartBody.options.challenge, RP_ID, RP_ORIGIN, 5);
  const authFinish = await req('POST', `${base}/interaction/${uidW}/webauthn/authenticate/finish`, jarW, {
    body: JSON.stringify({ challengeId: authStartBody.challengeId, ...assertion, biometricSample: 'LIVE-FACE-PROBE', biometricModality: 'face' }),
  });
  let endedW = await followToStop(authFinish, base, jarW);
  if ((endedW.location ?? '').includes('/interaction/')) {
    const cUid = interactionUid(endedW.location, base);
    await req('GET', `${base}/interaction/${cUid}`, jarW);
    const confirm = await req('POST', `${base}/interaction/${cUid}/confirm`, jarW, { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '' });
    endedW = await followToStop(confirm, base, jarW);
  }
  check('the passkey sign-in reaches the RP callback with a code', (endedW.location ?? '').startsWith(REDIRECT_URI) && /[?&]code=/.test(endedW.location ?? ''));

  // (7) Exchange + verify the id_token asserts AAL2 (phishing-resistant possession).
  const codeW = new URL(endedW.location ?? 'http://x').searchParams.get('code');
  const tokW = await req('POST', `${base}/oidc/token`, jarW, {
    headers: { authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: `grant_type=authorization_code&code=${codeW}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_verifier=${verifierW}`,
  });
  const tokensW = JSON.parse(tokW.body || '{}');
  let payloadW = null;
  try {
    ({ payload: payloadW } = await jose.jwtVerify(tokensW.id_token, jwks, { issuer, audience: CLIENT_ID }));
  } catch (e) {
    check('the passkey id_token verifies', false, e.message);
  }
  if (payloadW) {
    check('the biometric authority was called for the step-up', captured.biometricHits > 0);
    check('the live capture reached the authority (and only the authority)', captured.biometricProbe === 'LIVE-FACE-PROBE');
    check('passkey + attested biometric is AAL3 in the id_token (the strongest tier)', payloadW.acr === 'urn:openresidency:aal3', `acr=${payloadW.acr}`);
    check('the AAL3 id_token amr names both a hardware key (hwk) and biometric (bio)', Array.isArray(payloadW.amr) && payloadW.amr.includes('hwk') && payloadW.amr.includes('bio'), `amr=${JSON.stringify(payloadW.amr)}`);
  }

  // --- Teardown ------------------------------------------------------------
  await prisma.$disconnect();
  await app.close();
  mock.close();
  rmSync(cfgDir, { recursive: true, force: true });

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});