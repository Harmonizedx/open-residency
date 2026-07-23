/* eslint-disable no-console */
/**
 * Inji Draft-13 profile conformance.
 *
 * WHAT THIS IS. The codebase carries specific accommodations for MOSIP's Inji wallet --
 * RS256 key proofs, Draft-13 singular `proof`/`credential`, `did:jwk` for RSA keys, and
 * most unusually, emitting `c_nonce` and `client_id` INSIDE the access token because Inji
 * reads them from there rather than from the token response body. Each of those is
 * documented in docs/INTEROP.md, whose source is Inji's own published client code (the
 * Kotlin snippet quoted there). This test turns those scattered "Inji does X" claims into
 * an explicit, executable contract: a wallet that behaves exactly as Inji's documented
 * code does, driving the real issuer, asserting each accommodation -- and, crucially,
 * proving each is LOAD-BEARING with a negative test.
 *
 * WHAT THIS IS NOT. It is not a test against the live Inji app -- that needs the actual
 * mobile wallet against a MOSIP stack, which cannot run here. This verifies the issuer
 * against Inji's DOCUMENTED behavior (per its published source), which is the strongest
 * check possible without the device. If Inji's real behavior ever diverges from what its
 * source shows, only a live-device test would catch it; this pins everything up to that
 * line.
 */
import { SignJWT, generateKeyPair, exportJWK, decodeJwt, KeyLike, JWK } from 'jose';
import { createPublicKey } from 'node:crypto';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { InMemoryOid4vciStore } from '../src/core/oid4vci/ports';
import { Oid4vciService, PRE_AUTHORIZED_CODE_GRANT } from '../src/core/oid4vci/oid4vci-service';

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

const ISSUER = 'https://id.katsina.gov.ng';

function baseConfig(overrides: Record<string, unknown> = {}): CountryConfig {
  return parseCountryConfig({
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
    ...overrides,
  });
}

/** Stand up an issuer over a given config. */
function makeIssuer(cfg: CountryConfig) {
  const key = KeyStore.generate('issuer-key-1');
  return key.then((k) => {
    const residents = new InMemoryStore();
    const residency = new ResidencyService(
      new ProviderRegistry('inji-test-pepper'),
      new VcIssuer(k),
      residents,
      () => `${ISSUER}/.well-known/status/ng.json`,
      new LdpIssuer(k),
    );
    const vci = new Oid4vciService(
      { credentialIssuer: ISSUER },
      () => [cfg],
      (cc) => (cc.toUpperCase() === 'NG' ? cfg : undefined),
      residency,
      residents,
      new InMemoryOid4vciStore(),
      k,
    );
    return { key: k, residency, vci };
  });
}

/**
 * A faithful Inji key proof: RS256, typ openid4vci-proof+jwt, the public key inline as a
 * JWK header (Inji sends did:jwk-resolvable inline keys, not a kid), and -- per Inji's
 * client -- a non-standard `exp`.
 */
async function injiProof(opts: { privateKey: KeyLike; publicJwk: JWK; nonce: string }): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ nonce: opts.nonce })
    .setProtectedHeader({ alg: 'RS256', typ: 'openid4vci-proof+jwt', jwk: opts.publicJwk as any })
    .setAudience(ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + 300) // Inji adds a non-standard exp; the issuer must tolerate it
    .sign(opts.privateKey);
}

/**
 * Extract c_nonce the way Inji's client does, verbatim from the Kotlin quoted in
 * INTEROP.md:
 *   JWTParser.parse(accessToken).jwtClaimsSet.getClaim("c_nonce").toString()
 * Kotlin's `null.toString()` yields the literal string "null" -- so when the claim is
 * absent, the wallet signs its proof over the string "null". That is the failure the
 * cNonceInAccessToken accommodation exists to prevent, and this reproduces it exactly.
 */
function injiReadNonceFromAccessToken(accessToken: string): string {
  const claims = decodeJwt(accessToken) as Record<string, unknown>;
  const c = claims['c_nonce'];
  return c == null ? 'null' : String(c);
}

/** Redeem an offer to an access token, as a wallet does. */
async function getAccessToken(vci: Oid4vciService, residentId: string): Promise<string> {
  const offer = await vci.createOffer(residentId);
  const scanned = JSON.parse(new URL(offer.offerUri).searchParams.get('credential_offer')!);
  const code = scanned.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'];
  const tok = await vci.token({ grantType: PRE_AUTHORIZED_CODE_GRANT, preAuthorizedCode: code, txCode: offer.txCode });
  return tok.access_token as string;
}

async function enroll(residency: ResidencyService, cfg: CountryConfig): Promise<string> {
  const e = await residency.issue(cfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: '12345678902' } });
  if (e.status !== 'issued') throw new Error('enrollment failed');
  return e.residentId;
}

async function main() {
  console.log('\n== Inji Draft-13 profile conformance (documented behavior, not the live app) ==\n');

  // ========================================================================
  // Profile A: the default deployment -- serves Inji.
  // ========================================================================
  console.log('Default profile (serves Inji):');
  const A = await makeIssuer(baseConfig());
  const residentId = await enroll(A.residency, baseConfig());

  // Metadata: the accommodations Inji needs are advertised.
  const meta = A.vci.credentialIssuerMetadata();
  const configs = meta.credential_configurations_supported as Record<string, any>;
  check('offers an ldp_vc configuration (Inji rejects jwt_vc_json)', 'NG_StateResidencyCredential_ldp_vc' in configs);
  check(
    'advertises RS256 in proof algs (Inji hardcodes RS256)',
    configs['NG_StateResidencyCredential_ldp_vc'].proof_types_supported.jwt.proof_signing_alg_values_supported.includes('RS256'),
  );
  check('declares claims in the Draft 13 position (Inji reads them there)', configs['NG_StateResidencyCredential_ldp_vc'].claims != null);

  // The access token: c_nonce and client_id are INSIDE it, where Inji reads them.
  const at = await getAccessToken(A.vci, residentId);
  const atClaims = decodeJwt(at) as Record<string, unknown>;
  check('access token carries c_nonce as a claim (Inji reads it from here, not the body)', typeof atClaims.c_nonce === 'string');
  check('access token carries client_id as a claim (Inji reads it from here too)', typeof atClaims.client_id === 'string');

  // The wallet reads the nonce exactly as Inji does, and signs an RS256 proof.
  const nonce = injiReadNonceFromAccessToken(at);
  check('Inji reads a real c_nonce from the access token (not the literal "null")', nonce !== 'null' && nonce.length > 0);

  const walletB = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const walletBJwk = await exportJWK(walletB.publicKey);
  const proof = await injiProof({ privateKey: walletB.privateKey, publicJwk: walletBJwk, nonce });

  // Draft-13 request shape: singular `proof` + `format`.
  const res = await A.vci.credential(`Bearer ${at}`, {
    format: 'ldp_vc',
    credential_definition: { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'StateResidencyCredential'] },
    proof: { proof_type: 'jwt', jwt: proof },
  });
  check('Draft 13 singular `proof` request is accepted', res.credential != null);
  check('Draft 13 singular `credential` response (not a `credentials` array)', res.credential != null && (res as any).credentials === undefined);
  check('Draft 13 response echoes the `format`', (res as any).format === 'ldp_vc');
  check('Draft 13 response carries a fresh c_nonce', typeof (res as any).c_nonce === 'string');

  const vc = res.credential as LdpCredential;
  const subject = vc.credentialSubject as Record<string, unknown>;
  check('an RSA wallet key is bound via did:jwk (Inji sends inline JWK keys)', String(subject.id).startsWith('did:jwk:'));
  const issuerPub = createPublicKey({ key: A.key.publicJwk as any, format: 'jwk' });
  check('the Inji-issued credential verifies against the issuer key', await LdpIssuer.verify(vc, issuerPub));
  console.log('');

  // ========================================================================
  // Profile B: the accommodations are LOAD-BEARING.
  // Turn cNonceInAccessToken OFF and prove the exact Inji failure mode returns.
  // ========================================================================
  console.log('Accommodation is load-bearing (cNonceInAccessToken OFF reproduces the Inji failure):');
  const B = await makeIssuer(
    baseConfig({ wallet: { compatibility: { cNonceInAccessToken: false } } }),
  );
  const residentId2 = await enroll(B.residency, baseConfig({ wallet: { compatibility: { cNonceInAccessToken: false } } }));
  const at2 = await getAccessToken(B.vci, residentId2);

  const at2Claims = decodeJwt(at2) as Record<string, unknown>;
  check('with the accommodation off, the access token carries NO c_nonce claim', at2Claims.c_nonce === undefined);

  // Inji, finding no c_nonce claim, signs the literal string "null" (Kotlin null.toString()).
  const nonce2 = injiReadNonceFromAccessToken(at2);
  check('Inji then signs its key proof over the literal string "null"', nonce2 === 'null');

  const walletC = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const proofNull = await injiProof({ privateKey: walletC.privateKey, publicJwk: await exportJWK(walletC.publicKey), nonce: nonce2 });

  let rejected = false;
  let code = '';
  try {
    await B.vci.credential(`Bearer ${at2}`, {
      format: 'ldp_vc',
      credential_definition: { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'StateResidencyCredential'] },
      proof: { proof_type: 'jwt', jwt: proofNull },
    });
  } catch (e) {
    rejected = true;
    code = (e as { code?: string }).code ?? (e as Error).message;
  }
  check('the issuer REJECTS the "null"-nonce proof (this is the "enrollment failed" Inji hits)', rejected, `code=${code}`);
  check('...which is exactly why cNonceInAccessToken exists: it is not decoration', rejected);
  console.log('');

  // ========================================================================
  // Profile C: a deployment that does NOT serve Inji can narrow the surface.
  // ========================================================================
  console.log('A non-Inji deployment can drop the accommodations:');
  const C = await makeIssuer(baseConfig({ wallet: { formats: ['ldp_vc'], proofAlgs: ['EdDSA'] } }));
  const cCfgMeta = C.vci.credentialIssuerMetadata();
  const cLdp = (cCfgMeta.credential_configurations_supported as Record<string, any>)['NG_StateResidencyCredential_ldp_vc'];
  check('RS256 can be dropped from proof algs when no Inji is served', !cLdp.proof_types_supported.jwt.proof_signing_alg_values_supported.includes('RS256'));
  check('EdDSA remains (the standard, compact choice)', cLdp.proof_types_supported.jwt.proof_signing_alg_values_supported.includes('EdDSA'));

  console.log(`\n== ${pass} passed, ${fail} failed ==`);
  console.log('   (conformance to Inji\'s DOCUMENTED Draft-13 behavior; not a test against the live app)\n');
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
