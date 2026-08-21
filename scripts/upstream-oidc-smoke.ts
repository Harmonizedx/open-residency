/* eslint-disable no-console */
/**
 * Signing a resident in at an EXTERNAL OpenID Provider.
 *
 * The provider stood up here behaves the way eSignet's PUBLISHED configuration says it
 * behaves, and is strict about each of those points rather than permissive:
 *
 *   - `private_key_jwt` is the only client authentication it accepts, RS256, with the
 *     assertion audienced at the token endpoint. A request without one is refused.
 *   - PKCE is enforced: a code redeemed without the matching verifier is refused.
 *   - the id_token is RS256 and carries `acr`.
 *   - userinfo is a NESTED JWT -- signed by the OP, then encrypted to the relying party --
 *     which is the shape that catches implementations that assume JSON.
 *   - `sub` is pairwise: scoped to this relying party, not a national identifier.
 *
 * As with the Inji issuance profile, the honest boundary is that this verifies the client
 * against eSignet's DOCUMENTED behavior, not against a live MOSIP deployment. What it does
 * establish is that the flow is complete and that every failure mode fails closed, which is
 * the part that cannot be tested later against a sandbox without a partner agreement.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { SignJWT, CompactEncrypt, exportJWK, importPKCS8, importSPKI, JWK } from 'jose';
import {
  UpstreamOidcClient,
  InMemoryPendingUpstreamAuthStore,
  UpstreamOidcConfig,
  assertUpstreamOidcUsable,
} from '../src/core/oidc/upstream-oidc';
import { parseCountryConfig } from '../src/core/config/country-config';
import { OidcFoundationalAdapter } from '../src/core/foundational/adapters/oidc.adapter';
import { tokenizeSubject } from '../src/core/foundational/util';

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

const CLIENT_ID = 'openresidency-katsina';
const REDIRECT_URI = 'https://id.katsina.gov.ng/sso/upstream/callback';
const SUBJECT = 'pairwise-subject-for-this-rp-only';
/** Whether the OP releases an authoritative identifier alongside the profile claims. */
let releaseNationalId = true;
const INDIVIDUAL_ID = '2847100493';
const ACR_BIOMETRIC = 'mosip:idp:acr:biometrics';
const ACR_OTP = 'mosip:idp:acr:generated-code';
const ACR_UNMAPPED = 'mosip:idp:acr:linked-wallet';

function rsaPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/** One issued authorization code and what the OP will say about it. */
interface CodeRecord {
  codeChallenge: string;
  nonce: string;
  acr: string;
  sub: string;
}

async function main() {
  console.log('\nUpstream OIDC sign-in (external provider, eSignet-shaped):\n');

  const opSigning = rsaPair(); // the OP signs id_token and userinfo with this
  const rpAssertion = rsaPair(); // the RP signs its client assertion with this
  const rpEncryption = rsaPair(); // the OP encrypts userinfo to this

  const opPrivate = await importPKCS8(opSigning.privateKey, 'RS256');
  const opPublicJwk = (await exportJWK(await importSPKI(opSigning.publicKey, 'RS256'))) as JWK;
  opPublicJwk.kid = 'op-key-1';
  opPublicJwk.alg = 'RS256';
  opPublicJwk.use = 'sig';

  const rpAssertionPublic = await importSPKI(rpAssertion.publicKey, 'RS256');
  const rpEncryptionPublic = await importSPKI(rpEncryption.publicKey, 'RSA-OAEP-256');

  process.env.UPSTREAM_CLIENT_ASSERTION_KEY = rpAssertion.privateKey;
  process.env.UPSTREAM_USERINFO_DECRYPTION_KEY = rpEncryption.privateKey;

  const codes = new Map<string, CodeRecord>();
  const accessTokens = new Map<string, string>(); // access token -> sub
  // Records what the OP actually received, so the test can assert on the wire, not just
  // on the outcome.
  const seen: { assertionAud?: string; assertionAlg?: string; usedPkce?: boolean } = {};

  let issuer = '';

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', issuer);

    if (url.pathname === '/oauth/v2/token') {
      const body = await new Promise<string>((resolve) => {
        let data = '';
        req.on('data', (c) => (data += c));
        req.on('end', () => resolve(data));
      });
      const form = new URLSearchParams(body);

      const assertion = form.get('client_assertion');
      const assertionType = form.get('client_assertion_type');
      if (
        !assertion ||
        assertionType !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      ) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_client' }));
        return;
      }
      // Verify the assertion exactly as eSignet would: RS256, signed by the key the RP
      // registered, audienced at this endpoint.
      const { jwtVerify } = await import('jose');
      try {
        const verified = await jwtVerify(assertion, rpAssertionPublic, {
          issuer: CLIENT_ID,
          subject: CLIENT_ID,
          audience: `${issuer}/oauth/v2/token`,
        });
        seen.assertionAud = String(verified.payload.aud);
        seen.assertionAlg = String(verified.protectedHeader.alg);
      } catch (e) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_client', detail: (e as Error).message }));
        return;
      }

      const record = codes.get(form.get('code') ?? '');
      if (!record) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      codes.delete(form.get('code') ?? '');

      // PKCE, enforced.
      const verifier = form.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      seen.usedPkce = !!verifier;
      if (challenge !== record.codeChallenge) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant', detail: 'pkce' }));
        return;
      }

      const idToken = await new SignJWT({ nonce: record.nonce, acr: record.acr })
        .setProtectedHeader({ alg: 'RS256', kid: 'op-key-1' })
        .setIssuer(issuer)
        .setAudience(CLIENT_ID)
        .setSubject(record.sub)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(opPrivate);

      const accessToken = `at_${Math.abs(Number(BigInt(`0x${createHash('sha256').update(idToken).digest('hex').slice(0, 12)}`)))}`;
      accessTokens.set(accessToken, record.sub);

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          access_token: accessToken,
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 300,
        }),
      );
      return;
    }

    if (url.pathname === '/oidc/userinfo') {
      const auth = req.headers.authorization ?? '';
      const sub = accessTokens.get(auth.replace(/^Bearer /, ''));
      if (!sub) {
        res.writeHead(401);
        res.end();
        return;
      }
      // Signed, then encrypted to the RP: a nested JWT.
      const signed = await new SignJWT({
        sub,
        ...(releaseNationalId ? { individual_id: INDIVIDUAL_ID } : {}),
        name: 'Amina Bello',
        given_name: 'Amina',
        family_name: 'Bello',
        birthdate: '1990-04-11',
        gender: 'female',
        phone_number: '+2348030000000',
        email: 'amina@example.gov.ng',
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'op-key-1' })
        .setIssuer(issuer)
        .setAudience(CLIENT_ID)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(opPrivate);

      const encrypted = await new CompactEncrypt(new TextEncoder().encode(signed))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
        .encrypt(rpEncryptionPublic);

      res.writeHead(200, { 'content-type': 'application/jwt' });
      res.end(encrypted);
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  issuer = `http://127.0.0.1:${port}`;

  const config: UpstreamOidcConfig = {
    issuer,
    authorizationEndpoint: `${issuer}/authorize`,
    tokenEndpoint: `${issuer}/oauth/v2/token`,
    userinfoEndpoint: `${issuer}/oidc/userinfo`,
    jwks: [opPublicJwk],
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: ['profile', 'phone'],
    acrValues: [ACR_BIOMETRIC, ACR_OTP],
    acrMapping: [
      { acr: ACR_BIOMETRIC, assurance: 'high' },
      { acr: ACR_OTP, assurance: 'verified' },
    ],
    clientAssertionKeyEnv: 'UPSTREAM_CLIENT_ASSERTION_KEY',
    userinfoDecryptionKeyEnv: 'UPSTREAM_USERINFO_DECRYPTION_KEY',
  };

  const store = new InMemoryPendingUpstreamAuthStore();
  const client = new UpstreamOidcClient(config, store, 'test-pepper');

  /** Drive the browser leg the OP would: consume the authorize URL, mint a code. */
  function authorize(start: { authorizationUrl: string }, acr: string, sub = SUBJECT): string {
    const url = new URL(start.authorizationUrl);
    const code = `code_${url.searchParams.get('state')?.slice(0, 8)}_${acr.slice(-6)}`;
    codes.set(code, {
      codeChallenge: url.searchParams.get('code_challenge') ?? '',
      nonce: url.searchParams.get('nonce') ?? '',
      acr,
      sub,
    });
    return code;
  }

  // ---- The authorization request -------------------------------------------
  const start = await client.beginLogin();
  const authUrl = new URL(start.authorizationUrl);
  check('the authorization request asks for a code', authUrl.searchParams.get('response_type') === 'code');
  check('it sends the client id and the registered redirect', authUrl.searchParams.get('client_id') === CLIENT_ID && authUrl.searchParams.get('redirect_uri') === REDIRECT_URI);
  check('openid is always in the scope', (authUrl.searchParams.get('scope') ?? '').split(' ').includes('openid'));
  check('the requested acr values are sent space-separated', authUrl.searchParams.get('acr_values') === `${ACR_BIOMETRIC} ${ACR_OTP}`);
  check('PKCE S256 is used', authUrl.searchParams.get('code_challenge_method') === 'S256' && !!authUrl.searchParams.get('code_challenge'));
  check('state and nonce are both present and distinct', !!authUrl.searchParams.get('state') && !!authUrl.searchParams.get('nonce') && authUrl.searchParams.get('state') !== authUrl.searchParams.get('nonce'));
  check('the code verifier itself is never sent to the browser', !start.authorizationUrl.includes('code_verifier'));

  // ---- The happy path ------------------------------------------------------
  const code = authorize(start, ACR_BIOMETRIC);
  const result = await client.completeLogin({ code, state: start.state });
  check('a resident signs in through the external provider', result.authenticated, result.reason);
  check('the client authenticated with private_key_jwt, RS256', seen.assertionAlg === 'RS256');
  check('the client assertion is audienced at the token endpoint', seen.assertionAud === `${issuer}/oauth/v2/token`);
  check('the code was redeemed with the PKCE verifier', seen.usedPkce === true);
  check('the acr the provider reported is carried through', result.acr === ACR_BIOMETRIC);
  check('the acr maps to the assurance this deployment configured', result.assurance === 'high');
  check(
    'the sign-in is recorded as authoritative authentication, not a lookup',
    result.binding?.method === 'authoritative_authentication',
  );
  check(
    'demographics come back from the encrypted, signed userinfo response',
    result.identity?.fullName === 'Amina Bello' &&
      result.identity?.dateOfBirth === '1990-04-11' &&
      result.identity?.phone === '+2348030000000',
    JSON.stringify(result.identity),
  );
  check(
    'the raw upstream subject is never stored: the reference is tokenized',
    !!result.identity?.authenticationRef &&
      !result.identity.authenticationRef.includes(SUBJECT) &&
      result.identity.authenticationRef.startsWith('oidc_'),
    result.identity?.authenticationRef,
  );

  // The same subject at the same provider is stable; the pepper keeps it uncorrelatable.
  const start2 = await client.beginLogin();
  const second = await client.completeLogin({
    code: authorize(start2, ACR_OTP),
    state: start2.state,
  });
  // ADR-0010: this is an AUTHENTICATION reference, not a residency identity. The assertion
  // below is about session-subject stability at one OP, which is all a pairwise sub can
  // support -- it is not, and must never be read as, "the same person the register holds".
  check('the same upstream subject yields the same reference', second.identity?.authenticationRef === result.identity?.authenticationRef);
  check('a different acr yields the assurance mapped to it', second.assurance === 'verified');

  const otherPepper = new UpstreamOidcClient(config, store, 'a-different-deployment');
  const startOther = await otherPepper.beginLogin();
  const otherResult = await otherPepper.completeLogin({
    code: authorize(startOther, ACR_OTP),
    state: startOther.state,
  });
  check(
    'another deployment derives a DIFFERENT reference for the same person',
    otherResult.identity?.authenticationRef !== result.identity?.authenticationRef,
  );

  // ---- Failing closed ------------------------------------------------------
  console.log('\n  -- failing closed');

  const replay = await client.completeLogin({ code, state: start.state });
  check('a replayed callback is refused: state is single-use', !replay.authenticated && replay.reason === 'UNKNOWN_STATE', replay.reason);

  const forged = await client.completeLogin({ code: 'anything', state: 'never-issued' });
  check('a state we never issued is refused', !forged.authenticated && forged.reason === 'UNKNOWN_STATE');

  // A conformant OP echoes `state` on an error redirect too (RFC 6749 s4.1.2.1), so the
  // realistic case carries one -- and it is consumed like any other.
  const errStart = await client.beginLogin();
  const errored = await client.completeLogin({ error: 'access_denied', state: errStart.state });
  check('an error response from the provider is reported, not treated as a sign-in', !errored.authenticated && errored.reason === 'UPSTREAM_ERROR:access_denied');

  const erroredReplay = await client.completeLogin({ error: 'access_denied', state: errStart.state });
  check(
    'and its state is single-use like any other: the error callback cannot be replayed',
    !erroredReplay.authenticated && erroredReplay.reason === 'UNKNOWN_STATE',
  );

  // The callback route is unguarded by design -- a browser redirect lands there -- and the
  // caller audits every outcome into a hash-chained log. Without this, ?error=<anything>
  // with no state at all was an unauthenticated, repeatable write of attacker-chosen text
  // into that chain.
  const statelessError = await client.completeLogin({ error: 'anything-i-like' });
  check(
    'an error callback with no state is refused before anything is recorded',
    !statelessError.authenticated && statelessError.reason === 'MISSING_STATE',
  );

  // A repeated query parameter arrives as an array, not a string. Refused rather than
  // coerced: a conformant OP sends each once, and operating on the wrong shape would make
  // the cap truncate an array and the state comparison stop meaning what it reads as.
  const arrayStart = await client.beginLogin();
  const arrayState = await client.completeLogin({
    error: ['a', 'b'] as unknown as string,
    state: [arrayStart.state, 'other'] as unknown as string,
  });
  check(
    'a repeated query parameter is refused, not treated as a string',
    !arrayState.authenticated && arrayState.reason === 'MISSING_STATE',
  );
  check(
    'and the state it named was not consumed by the attempt',
    await client
      .completeLogin({ error: 'access_denied', state: arrayStart.state })
      .then((r) => r.reason === 'UPSTREAM_ERROR:access_denied'),
  );

  const longStart = await client.beginLogin();
  const longError = await client.completeLogin({ error: 'x'.repeat(5000), state: longStart.state });
  check(
    'a provider error string is capped before it reaches an audit row',
    (longError.reason ?? '').length <= 'UPSTREAM_ERROR:'.length + 64,
  );

  const startNonce = await client.beginLogin();
  const nonceCode = authorize(startNonce, ACR_BIOMETRIC);
  codes.get(nonceCode)!.nonce = 'a-nonce-from-a-different-session';
  const nonceResult = await client.completeLogin({ code: nonceCode, state: startNonce.state });
  check(
    'an id_token whose nonce is from another session is refused',
    !nonceResult.authenticated && nonceResult.reason === 'NONCE_MISMATCH',
    nonceResult.reason,
  );

  const startAcr = await client.beginLogin();
  const acrResult = await client.completeLogin({
    code: authorize(startAcr, ACR_UNMAPPED),
    state: startAcr.state,
  });
  check(
    'an acr the deployment never mapped is refused, not graded down',
    !acrResult.authenticated && acrResult.reason === `UNMAPPED_ACR:${ACR_UNMAPPED}`,
    acrResult.reason,
  );

  // A provider that returns a different subject from userinfo than from the id_token is
  // either broken or substituting people; either way it is not a sign-in.
  const startSwap = await client.beginLogin();
  const swapCode = authorize(startSwap, ACR_BIOMETRIC, 'subject-A');
  const swapped = await (async () => {
    const original = accessTokens.set.bind(accessTokens);
    accessTokens.set = (k: string, _v: string) => original(k, 'subject-B');
    try {
      return await client.completeLogin({ code: swapCode, state: startSwap.state });
    } finally {
      accessTokens.set = original;
    }
  })();
  check(
    'a provider that switches subject between id_token and userinfo is refused',
    !swapped.authenticated && swapped.reason === 'USERINFO_SUBJECT_MISMATCH',
    swapped.reason,
  );

  // An id_token signed by a key we have not pinned must not verify, even though the OP
  // otherwise behaves. This is the check that makes the pinned JWKS load-bearing.
  const impostor = rsaPair();
  const impostorKey = await importPKCS8(impostor.privateKey, 'RS256');
  const startImpostor = await client.beginLogin();
  const impostorAuthUrl = new URL(startImpostor.authorizationUrl);
  const impostorToken = await new SignJWT({
    nonce: impostorAuthUrl.searchParams.get('nonce') ?? '',
    acr: ACR_BIOMETRIC,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'op-key-1' })
    .setIssuer(issuer)
    .setAudience(CLIENT_ID)
    .setSubject(SUBJECT)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(impostorKey);

  const impostorClient = new UpstreamOidcClient(config, store, 'test-pepper', (async () =>
    new Response(JSON.stringify({ id_token: impostorToken, token_type: 'Bearer' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch);
  const impostorResult = await impostorClient.completeLogin({
    code: 'irrelevant',
    state: startImpostor.state,
  });
  check(
    'an id_token signed by an unpinned key is refused',
    !impostorResult.authenticated && impostorResult.reason?.startsWith('ID_TOKEN_INVALID') === true,
    impostorResult.reason,
  );

  // Configuration that cannot express a policy is refused at construction, not at 3am.
  let refusedEmptyMapping = false;
  try {
    new UpstreamOidcClient({ ...config, acrMapping: [] }, store, 'test-pepper');
  } catch {
    refusedEmptyMapping = true;
  }
  check('a config with no acr mapping is refused at construction', refusedEmptyMapping);

  let refusedNoJwks = false;
  try {
    new UpstreamOidcClient({ ...config, jwks: [] }, store, 'test-pepper');
  } catch {
    refusedNoJwks = true;
  }
  check('a config with no pinned provider keys is refused at construction', refusedNoJwks);

  // A missing client-assertion key must surface as a token-request failure, not a crash.
  const savedKey = process.env.UPSTREAM_CLIENT_ASSERTION_KEY;
  delete process.env.UPSTREAM_CLIENT_ASSERTION_KEY;
  const startNoKey = await client.beginLogin();
  const noKey = await client.completeLogin({
    code: authorize(startNoKey, ACR_BIOMETRIC),
    state: startNoKey.state,
  });
  process.env.UPSTREAM_CLIENT_ASSERTION_KEY = savedKey;
  check(
    'a missing client assertion key fails the sign-in with a reason, not an exception',
    !noKey.authenticated && noKey.reason?.startsWith('TOKEN_REQUEST_FAILED') === true,
    noKey.reason,
  );

  // ---- The wiring: YAML-shaped config reaches the client --------------------
  console.log('\n  -- configuration');
  const cfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid: 'did:web:id.katsina.gov.ng',
      issuerName: 'Katsina',
      type: 'StateResidencyCredential',
      validityDays: 1095,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
    upstreamOidc: {
      issuer,
      authorizationEndpoint: `${issuer}/authorize`,
      tokenEndpoint: `${issuer}/oauth/v2/token`,
      userinfoEndpoint: `${issuer}/oidc/userinfo`,
      jwks: [opPublicJwk],
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      acrValues: [ACR_BIOMETRIC],
      acrMapping: [{ acr: ACR_BIOMETRIC, assurance: 'high' }],
      clientAssertionKeyEnv: 'UPSTREAM_CLIENT_ASSERTION_KEY',
      userinfoDecryptionKeyEnv: 'UPSTREAM_USERINFO_DECRYPTION_KEY',
    },
  });
  check('an upstream provider parses from config', !!cfg.upstreamOidc);
  check(
    'the acr mapping survives config parsing',
    cfg.upstreamOidc?.acrMapping[0].assurance === 'high',
  );

  const fromConfig = new UpstreamOidcClient(
    cfg.upstreamOidc as unknown as UpstreamOidcConfig,
    store,
    'test-pepper',
  );
  const configStart = await fromConfig.beginLogin();
  const configResult = await fromConfig.completeLogin({
    code: authorize(configStart, ACR_BIOMETRIC),
    state: configStart.state,
  });
  check(
    'a resident signs in through a client built entirely from config',
    configResult.authenticated,
    configResult.reason,
  );

  // A config that lists no acr mapping cannot express what a sign-in is worth, and the
  // schema refuses it rather than leaving the decision to a default.
  let refusedBySchema = false;
  try {
    parseCountryConfig({
      countryCode: 'NG',
      countryName: 'Nigeria',
      foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
      residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
      credential: { issuerDid: 'did:web:x', issuerName: 'X', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
      subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
      upstreamOidc: {
        issuer,
        authorizationEndpoint: `${issuer}/authorize`,
        tokenEndpoint: `${issuer}/oauth/v2/token`,
        jwks: [opPublicJwk],
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        acrMapping: [],
        clientAssertionKeyEnv: 'UPSTREAM_CLIENT_ASSERTION_KEY',
      },
    });
  } catch {
    refusedBySchema = true;
  }
  check('a config with an empty acr mapping is refused at load', refusedBySchema);

  // --- Declared but unusable config is refused at BOOT, not at first sign-in ----
  //
  // The keys are named as environment variables, so the schema cannot check they exist.
  // Until this guard, a deployment could point upstreamOidc at its national IdP, watch it
  // validate, and discover months later -- from the first resident who could not sign in --
  // that a key was never set.
  console.log('\nBoot guard on declared-but-unusable config:');
  {
    // userinfoDecryptionKeyEnv cleared: the base config declares one (it exercises the
    // nested-JWT path), and leaving it would make every case below fail on that branch
    // instead of the one under test.
    const usable = {
      ...config,
      clientAssertionKeyEnv: 'UP_KEY',
      userinfoDecryptionKeyEnv: undefined,
    };
    const threwFor = (env: NodeJS.ProcessEnv): string | null => {
      try {
        assertUpstreamOidcUsable(usable as UpstreamOidcConfig, env);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    };

    const missing = threwFor({});
    check('a missing client-assertion key refuses to boot', missing !== null);
    check('and the error names the variable to set', !!missing && missing.includes('UP_KEY'));

    check('a config whose key IS set boots', threwFor({ UP_KEY: 'pem' }) === null);

    const withDecrypt = { ...usable, userinfoDecryptionKeyEnv: 'UP_DEC' };
    let decMsg: string | null = null;
    try {
      assertUpstreamOidcUsable(withDecrypt as UpstreamOidcConfig, { UP_KEY: 'pem' });
    } catch (e) {
      decMsg = (e as Error).message;
    }
    check('declaring userinfo decryption without the key refuses to boot', decMsg !== null);
    check('and names that variable too', !!decMsg && decMsg.includes('UP_DEC'));
  }


  // ---- The same OP as the foundational register (#116, ADR-0010) -----------
  // Everything above proves the client. This drives the FoundationalProvider that sits on
  // top of it, through the same real HTTP, real signed id_token and real nested-JWT
  // userinfo -- not a stubbed client -- because the thing under test is which value out of
  // that exchange becomes the residency identity.
  console.log('\nThe OP as a foundational register:');

  const registerConfig: UpstreamOidcConfig = {
    ...config,
    claimMapping: { nationalId: 'individual_id' },
  };
  const registerClient = new UpstreamOidcClient(registerConfig, store, 'test-pepper');
  const adapter = new OidcFoundationalAdapter('ESIGNET', registerClient, 'test-pepper');
  adapter.init({ code: 'ESIGNET', assuranceOnSuccess: 'verified' });

  const challenge = await adapter.initiateChallenge!({ countryCode: 'NG', identifiers: {} });
  check(
    'the challenge step returns the OP authorization URL and the state as its reference',
    challenge.channel.startsWith(`${issuer}/authorize`) && !!challenge.challengeRef,
  );

  const regCode = authorize({ authorizationUrl: challenge.channel }, ACR_BIOMETRIC);
  const regResult = await adapter.verify({
    countryCode: 'NG',
    identifiers: { code: regCode },
    challengeRef: challenge.challengeRef,
  });
  check('a real sign-in through the OP yields a verified foundational result', regResult.verified);
  check(
    'the residency identity is keyed on the identifier the OP released, not its subject',
    regResult.identity?.subjectRef === tokenizeSubject('OIDC', INDIVIDUAL_ID, 'test-pepper'),
  );
  check(
    'and it is namespaced by the provider, never by the OP issuer hash',
    (regResult.identity?.subjectRef ?? '').startsWith('oidc:') &&
      !(regResult.identity?.subjectRef ?? '').includes('oidc_'),
  );
  check(
    'the profile claims decrypted out of the nested JWT reach the identity',
    regResult.identity?.fullName === 'Amina Bello' && regResult.identity?.dateOfBirth === '1990-04-11',
  );
  check(
    'the redirect supplies the applicant binding a register lookup cannot',
    regResult.applicantBinding?.method === 'authoritative_authentication',
  );
  check('the acr the OP reported still sets the assurance', regResult.assuranceLevel === 'high');

  // Same OP, same flow, one difference: it releases no identifier.
  releaseNationalId = false;
  const bareChallenge = await adapter.initiateChallenge!({ countryCode: 'NG', identifiers: {} });
  const bareCode = authorize({ authorizationUrl: bareChallenge.channel }, ACR_BIOMETRIC);
  const bare = await adapter.verify({
    countryCode: 'NG',
    identifiers: { code: bareCode },
    challengeRef: bareChallenge.challengeRef,
  });
  check(
    'an OP that authenticates but releases no identifier is refused, never keyed on sub',
    !bare.verified && bare.reason === 'NO_AUTHORITATIVE_IDENTIFIER',
  );
  check('the refusal carries no identity to fall back on', bare.identity === undefined);
  check(
    'the raw identifier never rides inside the identity object the callback route returns',
    !JSON.stringify(regResult.identity ?? {}).includes(INDIVIDUAL_ID),
  );
  releaseNationalId = true;

  server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});