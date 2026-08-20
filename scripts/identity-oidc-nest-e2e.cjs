/* eslint-disable no-console */
/**
 * Full-stack end-to-end: an OpenID Connect provider acting as the foundational REGISTER,
 * driven through the real NestJS application (#116, ADR-0010).
 *
 * The suites in scripts/*.ts exercise the adapter and the client directly. Neither boots the
 * app, so neither can catch the failure this exists for: `foundational.provider: ESIGNET` is
 * resolved through the ProviderRegistry, and the client-backed adapter is registered by
 * PlatformService during boot. A wiring defect there leaves the provider resolving to the
 * generic REST fallback with every hermetic suite still green.
 *
 * So this drives the two real endpoints a registrar's UI calls --
 *   POST /identity/challenge  -> the authorization URL to send the applicant to
 *   POST /identity/verify     -> the callback, turned into a foundational identity
 * -- against an OP that signs real tokens, and asserts the identity is keyed on the
 * identifier the OP releases rather than on its pairwise subject.
 *
 * Requires PostgreSQL; run through scripts/run-sso-nest-e2e.sh, which provides one.
 */
const { createServer } = require('node:http');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { generateKeyPairSync } = require('node:crypto');

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
}

const PEPPER = 'identity-oidc-e2e-pepper';
const CLIENT_ID = 'openresidency-e2e';
const INDIVIDUAL_ID = '2847100493';
const ACR = 'mosip:idp:acr:biometrics';
const SUBJECT = 'pairwise-sub-for-this-rp-only';

function rsaPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

async function post(base, path, body) {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

async function main() {
  const { SignJWT, exportJWK, importPKCS8, importSPKI } = require('jose');

  const op = rsaPair();          // the OP signs id_token and userinfo with this
  const rp = rsaPair();          // the RP authenticates to the token endpoint with this
  const opPrivate = await importPKCS8(op.privateKey, 'RS256');
  const opPublicJwk = { ...(await exportJWK(await importSPKI(op.publicKey, 'RS256'))), kid: 'op-key-1', alg: 'RS256', use: 'sig' };

  /** Whether the OP releases an authoritative identifier. Flipped to prove the refusal. */
  let releaseIdentifier = true;
  const codes = new Map();
  const accessTokens = new Map();

  // --- The OP -------------------------------------------------------------
  let issuer = '';
  const opServer = createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1`);

    if (url.pathname === '/oauth/v2/token') {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      const record = codes.get(form.get('code') ?? '');
      if (!record) { res.writeHead(400); res.end('{"error":"invalid_grant"}'); return; }

      const idToken = await new SignJWT({ nonce: record.nonce, acr: ACR })
        .setProtectedHeader({ alg: 'RS256', kid: 'op-key-1' })
        .setIssuer(issuer).setSubject(SUBJECT).setAudience(CLIENT_ID)
        .setIssuedAt().setExpirationTime('5m')
        .sign(opPrivate);

      const accessToken = `at_${Math.random().toString(36).slice(2)}`;
      accessTokens.set(accessToken, SUBJECT);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id_token: idToken, access_token: accessToken, token_type: 'Bearer' }));
      return;
    }

    if (url.pathname === '/oidc/userinfo') {
      const sub = accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
      if (!sub) { res.writeHead(401); res.end(); return; }
      const claims = {
        sub,
        ...(releaseIdentifier ? { individual_id: INDIVIDUAL_ID } : {}),
        name: 'Amina Bello',
        birthdate: '1990-04-11',
        gender: 'female',
      };
      const signed = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'op-key-1' })
        .setIssuer(issuer).setAudience(CLIENT_ID).setIssuedAt().setExpirationTime('5m')
        .sign(opPrivate);
      res.writeHead(200, { 'content-type': 'application/jwt' });
      res.end(signed);
      return;
    }

    res.writeHead(404); res.end();
  });
  await new Promise((r) => opServer.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${opServer.address().port}`;

  /** Drive the browser leg: consume the authorization URL the app produced, mint a code. */
  function authorize(authorizationUrl) {
    const u = new URL(authorizationUrl);
    const code = `code_${u.searchParams.get('state').slice(0, 10)}`;
    codes.set(code, { nonce: u.searchParams.get('nonce') });
    return code;
  }

  // --- A jurisdiction whose register IS that OP ---------------------------
  // mkdtempSync, not a pid-derived path: the directory name must not be predictable, or a
  // pre-created symlink at that path decides where this writes.
  const cfgDir = mkdtempSync(join(tmpdir(), 'ors-idoidc-cfg-'));
  writeFileSync(join(cfgDir, 'zz.yaml'), `countryCode: ZZ
countryName: Demoland
defaultSubnationalUnit: DX
foundational:
  provider: ESIGNET
  inputs: [{ key: code, label: Authorization code }]
  assuranceOnSuccess: verified
upstreamOidc:
  issuer: ${issuer}
  authorizationEndpoint: ${issuer}/authorize
  tokenEndpoint: ${issuer}/oauth/v2/token
  userinfoEndpoint: ${issuer}/oidc/userinfo
  jwks:
    - ${JSON.stringify(opPublicJwk)}
  clientId: ${CLIENT_ID}
  redirectUri: http://localhost:8080/enrolment/upstream/callback
  scopes: [profile]
  acrValues: ["${ACR}"]
  acrMapping:
    - { acr: "${ACR}", assurance: high }
  clientAssertionKeyEnv: UPSTREAM_CLIENT_ASSERTION_KEY
  claimMapping:
    nationalId: individual_id
    fullName: name
    dateOfBirth: birthdate
residency:
  minAssurance: verified
  proofOfResidence: attestation
  humanReview:
    path: 'e2e fixture: reconsideration would be requested at the enrolment desk'
    withinDays: 30
credential:
  issuerDid: did:web:id.demoland.example
  issuerName: Demoland Residency Authority
  type: StateResidencyCredential
  validityDays: 365
  context: [https://www.w3.org/ns/credentials/v2]
subnationalUnits:
  - { code: DX, name: Demo District, parent: ZZ, level: state }
`);

  process.env.NODE_ENV = 'test';
  process.env.COUNTRY_CONFIG_DIR = cfgDir;
  process.env.SUBJECT_PEPPER = PEPPER;
  process.env.ISSUER_KEY_BACKEND = 'dev';
  process.env.OIDC_COOKIE_SECRET = 'identity-oidc-e2e-cookie-secret-0123456789';
  process.env.ADMIN_API_KEY = 'identity-oidc-e2e-admin-key';
  process.env.PUBLIC_BASE_URL = 'http://localhost:8080';
  process.env.UPSTREAM_CLIENT_ASSERTION_KEY = rp.privateKey;

  // --- Boot the ACTUAL app ------------------------------------------------
  const { NestFactory } = require('@nestjs/core');
  const { json, urlencoded } = require('express');
  const { AppModule } = require('../dist/app.module');

  const app = await NestFactory.create(AppModule, { bodyParser: false, logger: false });
  app.use(json());
  app.use(urlencoded({ extended: false }));
  await app.listen(0, '127.0.0.1');
  const base = (await app.getUrl()).replace('[::1]', '127.0.0.1').replace('0.0.0.0', '127.0.0.1');

  console.log('\n== OpenResidency: an OIDC provider as the register (real NestJS app) ==\n');

  try {
    // The boot itself is the first assertion: PlatformService must have resolved ESIGNET
    // and registered the client-backed adapter, or /identity/challenge cannot work at all.
    const challenge = await post(base, '/identity/challenge', { countryCode: 'ZZ', identifiers: {} });
    check('POST /identity/challenge is served (the provider resolved and wired at boot)', challenge.status === 201 || challenge.status === 200);
    check('it reports that a challenge is required', challenge.body.challengeRequired === true);
    check(
      'the channel is the OP authorization URL, carrying PKCE and the client id',
      typeof challenge.body.channel === 'string' &&
        challenge.body.channel.startsWith(`${issuer}/authorize`) &&
        new URL(challenge.body.channel).searchParams.get('code_challenge_method') === 'S256' &&
        new URL(challenge.body.channel).searchParams.get('client_id') === CLIENT_ID,
    );

    const code = authorize(challenge.body.channel);
    const verified = await post(base, '/identity/verify', {
      countryCode: 'ZZ',
      identifiers: { code },
      challengeRef: challenge.body.challengeRef,
    });
    check('POST /identity/verify completes the sign-in', verified.body.verified === true);
    check(
      'the claims the OP released reach the caller, minimized',
      verified.body.attributes?.fullName === 'Amina Bello' &&
        verified.body.attributes?.dateOfBirth === '1990-04-11',
    );
    check(
      'the identity is namespaced by the provider, not by the OP issuer hash',
      typeof verified.body.subjectRef === 'string' &&
        verified.body.subjectRef.startsWith('oidc:') &&
        !verified.body.subjectRef.includes('oidc_'),
    );
    check(
      'the raw national identifier appears nowhere in the response',
      !JSON.stringify(verified.body).includes(INDIVIDUAL_ID),
    );
    // The endpoint deliberately does not surface applicantBinding -- the residency engine
    // reads it from the provider result inside issue(), and it is asserted there and in
    // smoke:upstream-oidc. What is observable here is the acr mapping surviving a real boot.
    check(
      'the acr the OP reported is mapped to the configured assurance',
      verified.body.assuranceLevel === 'high',
    );

    // Same OP, same flow, releasing no identifier.
    releaseIdentifier = false;
    const ch2 = await post(base, '/identity/challenge', { countryCode: 'ZZ', identifiers: {} });
    const code2 = authorize(ch2.body.channel);
    const refused = await post(base, '/identity/verify', {
      countryCode: 'ZZ',
      identifiers: { code: code2 },
      challengeRef: ch2.body.challengeRef,
    });
    check(
      'an OP that authenticates but releases no identifier is refused through the real endpoint',
      refused.body.verified === false && refused.body.reason === 'NO_AUTHORITATIVE_IDENTIFIER',
    );
    check('and no identity is returned to fall back on', refused.body.identity === undefined);
  } finally {
    await app.close();
    opServer.close();
    rmSync(cfgDir, { recursive: true, force: true });
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
