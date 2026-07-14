/* eslint-disable no-console */
/**
 * OpenID4VCI end-to-end check.
 *
 * This drives the issuer exactly as a wallet would: it scans the offer, redeems the
 * pre-authorized code with the PIN, asks for a nonce, signs a key proof, and requests a
 * credential -- then verifies what comes back. It runs the flow twice: once as a
 * spec-current 1.0 wallet (Ed25519, `proofs`, `credential_configuration_id`) and once
 * imitating Inji (RSA/RS256, Draft 13 `proof` + `format`, reading c_nonce out of the
 * access token JWT), because those are the two dialects a real deployment must serve.
 *
 * It then tries the attacks this design exists to stop: a replayed nonce, a replayed
 * pre-authorized code, a brute-forced PIN, an unbound credential request, and a proof
 * minted for a different audience.
 */
import { SignJWT, generateKeyPair, exportJWK, importJWK, KeyLike, JWK } from 'jose';
import { createPublicKey } from 'node:crypto';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { InMemoryOid4vciStore } from '../src/core/oid4vci/ports';
import { Oid4vciService, PRE_AUTHORIZED_CODE_GRANT } from '../src/core/oid4vci/oid4vci-service';
import { didKeyFromJwk } from '../src/core/credentials/did';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `  -- ${detail}` : ''}`);
  }
}

/** Assert that a call is rejected, and that it is rejected for the RIGHT reason. */
async function rejects(name: string, expectedCode: string, fn: () => Promise<unknown>) {
  try {
    await fn();
    check(name, false, 'call unexpectedly SUCCEEDED');
  } catch (e) {
    const code = (e as { code?: string }).code ?? '';
    check(name, code === expectedCode, `expected '${expectedCode}', got '${code}'`);
  }
}

const ISSUER = 'https://id.katsina.gov.ng';

const CONFIG: CountryConfig = parseCountryConfig({
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
    issuerName: 'Katsina State Residency Authority',
    type: 'StateResidencyCredential',
    validityDays: 1095,
    context: ['https://www.w3.org/ns/credentials/v2'],
  },
  subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
});

/** Build the key proof a wallet signs. */
async function makeProof(opts: {
  privateKey: KeyLike;
  publicJwk: JWK;
  alg: string;
  aud: string;
  nonce: string;
  iat?: number;
}): Promise<string> {
  return new SignJWT({ nonce: opts.nonce })
    .setProtectedHeader({
      alg: opts.alg,
      typ: 'openid4vci-proof+jwt',
      jwk: opts.publicJwk as any,
    })
    .setAudience(opts.aud)
    .setIssuedAt(opts.iat ?? Math.floor(Date.now() / 1000))
    .sign(opts.privateKey);
}

async function main() {
  console.log('\n== OpenID4VCI issuance: wallet-side end-to-end ==\n');

  // ---- Issuer under test -------------------------------------------------
  const key = await KeyStore.generate('issuer-key-1');
  const residents = new InMemoryStore();
  const vciStore = new InMemoryOid4vciStore();
  const residency = new ResidencyService(
    new ProviderRegistry('test-pepper'),
    new VcIssuer(key),
    residents,
    () => `${ISSUER}/.well-known/status/ng.json`,
    new LdpIssuer(key),
  );
  const vci = new Oid4vciService(
    { credentialIssuer: ISSUER },
    () => [CONFIG],
    (cc) => (cc.toUpperCase() === 'NG' ? CONFIG : undefined),
    residency,
    residents,
    vciStore,
    key,
  );

  // ---- Enrollment (the existing, unchanged path) -------------------------
  console.log('Enrollment at the desk (foundational ID check):');
  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    // The MOCK provider verifies identifiers ending in an even digit.
    identifiers: { nin: '12345678902' },
  });
  check('resident enrolled via the existing flow', enrolled.status === 'issued');
  if (enrolled.status !== 'issued') throw new Error('enrollment failed; cannot continue');
  const residentId = enrolled.residentId;
  console.log(`  residentId: ${residentId}\n`);

  // ---- Metadata ----------------------------------------------------------
  console.log('Issuer metadata:');
  const meta = vci.credentialIssuerMetadata();
  const configs = meta.credential_configurations_supported as Record<string, any>;
  check('credential_issuer matches the deployment origin', meta.credential_issuer === ISSUER);
  check('advertises a nonce_endpoint (1.0 wallets)', typeof meta.nonce_endpoint === 'string');
  check('offers an ldp_vc configuration (required by Inji)', 'NG_StateResidencyCredential_ldp_vc' in configs);
  check('offers a jwt_vc_json configuration', 'NG_StateResidencyCredential_jwt_vc_json' in configs);
  const ldpCfg = configs['NG_StateResidencyCredential_ldp_vc'];
  check(
    'advertises RS256 in proof algs (Inji hardcodes it)',
    ldpCfg.proof_types_supported.jwt.proof_signing_alg_values_supported.includes('RS256'),
  );
  check('declares claims in the Draft 13 position', ldpCfg.claims != null);
  check('declares claims in the 1.0 position too', ldpCfg.credential_metadata?.claims != null);
  const asMeta = vci.authorizationServerMetadata();
  check(
    'AS metadata advertises the pre-authorized grant',
    (asMeta.grant_types_supported as string[]).includes(PRE_AUTHORIZED_CODE_GRANT),
  );
  console.log('');

  // ---- Wallet A: a spec-current 1.0 wallet, Ed25519 -----------------------
  console.log('Wallet A -- OpenID4VCI 1.0, Ed25519, ldp_vc:');
  const offer = await vci.createOffer(residentId);

  // Scan the QR: parse the offer straight out of the deep link, as a wallet does.
  const offerUrl = new URL(offer.offerUri);
  const scanned = JSON.parse(offerUrl.searchParams.get('credential_offer')!);
  check('offer URI uses the openid-credential-offer scheme', offer.offerUri.startsWith('openid-credential-offer://'));
  check('scanned offer names this credential issuer', scanned.credential_issuer === ISSUER);
  const grant = scanned.grants[PRE_AUTHORIZED_CODE_GRANT];
  check('scanned offer carries a pre-authorized_code', typeof grant['pre-authorized_code'] === 'string');
  check('scanned offer demands a 6-digit numeric tx_code', grant.tx_code.length === 6 && grant.tx_code.input_mode === 'numeric');
  const preAuthCode: string = grant['pre-authorized_code'];

  const tokenRes = await vci.token({
    grantType: PRE_AUTHORIZED_CODE_GRANT,
    preAuthorizedCode: preAuthCode,
    txCode: offer.txCode,
  });
  check('token issued for a correct code + PIN', typeof tokenRes.access_token === 'string');
  const accessToken = tokenRes.access_token as string;

  const nonceRes = await vci.nonce();
  const cNonce = nonceRes.c_nonce as string;
  check('nonce endpoint returns a c_nonce', typeof cNonce === 'string' && cNonce.length > 0);

  const walletA = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const walletAJwk = await exportJWK(walletA.publicKey);
  const proofA = await makeProof({
    privateKey: walletA.privateKey,
    publicJwk: walletAJwk,
    alg: 'EdDSA',
    aud: ISSUER,
    nonce: cNonce,
  });

  const credResA = await vci.credential(`Bearer ${accessToken}`, {
    credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
    proofs: { jwt: [proofA] },
  });
  check('1.0 request answered with a `credentials` array', Array.isArray(credResA.credentials));
  const ldpVc = (credResA.credentials as { credential: LdpCredential }[])[0].credential;

  // The whole point: the credential is bound to the wallet's key, not to a bearer urn.
  const expectedDid = didKeyFromJwk(walletAJwk);
  const subject = ldpVc.credentialSubject as Record<string, unknown>;
  check('credential subject is the wallet did:key (holder-bound)', subject.id === expectedDid);
  check('credential carries the residency claims', subject.residentId === residentId);
  check('credential carries a status entry (revocable)', ldpVc.credentialStatus != null);

  // Verify the Data Integrity proof cryptographically.
  const issuerPub = createPublicKey({ key: key.publicJwk as any, format: 'jwk' });
  check('ldp_vc DataIntegrityProof verifies', await LdpIssuer.verify(ldpVc, issuerPub));

  // Tamper: flip a claim and the proof must stop verifying.
  const tampered = JSON.parse(JSON.stringify(ldpVc)) as LdpCredential;
  (tampered.credentialSubject as Record<string, unknown>).residentId = 'KT-FAKE-0000';
  check('tampered ldp_vc fails verification', !(await LdpIssuer.verify(tampered, issuerPub)));
  console.log('');

  // ---- Wallet B: imitating Inji -- Draft 13, RSA/RS256 --------------------
  console.log('Wallet B -- Inji-style: Draft 13 wire format, RS256:');
  const offerB = await vci.createOffer(residentId);
  const scannedB = JSON.parse(new URL(offerB.offerUri).searchParams.get('credential_offer')!);
  const tokenB = await vci.token({
    grantType: PRE_AUTHORIZED_CODE_GRANT,
    preAuthorizedCode: scannedB.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
    txCode: offerB.txCode,
  });

  // Inji does NOT read c_nonce from the response body -- it parses the access token JWT
  // and reads the claim from inside. If that claim is missing, the wallet signs a proof
  // with the literal string "null" and issuance fails. So: read it the way Inji does.
  const atPayload = JSON.parse(
    Buffer.from((tokenB.access_token as string).split('.')[1], 'base64url').toString(),
  );
  check('access token carries c_nonce as a claim (Inji reads it here)', typeof atPayload.c_nonce === 'string');
  check('access token carries client_id as a claim (Inji reads it here)', typeof atPayload.client_id === 'string');
  const injiNonce: string = atPayload.c_nonce;

  const walletB = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const walletBJwk = await exportJWK(walletB.publicKey);
  const proofB = await makeProof({
    privateKey: walletB.privateKey,
    publicJwk: walletBJwk,
    alg: 'RS256',
    aud: ISSUER,
    nonce: injiNonce,
  });

  const credResB = await vci.credential(`Bearer ${tokenB.access_token}`, {
    format: 'ldp_vc',
    credential_definition: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'StateResidencyCredential'],
    },
    proof: { proof_type: 'jwt', jwt: proofB },
  });
  check('Draft 13 request answered with a singular `credential`', credResB.credential != null);
  check('Draft 13 response carries a fresh c_nonce', typeof credResB.c_nonce === 'string');
  check('Draft 13 response echoes the format', credResB.format === 'ldp_vc');

  const injiVc = credResB.credential as LdpCredential;
  const injiSubject = injiVc.credentialSubject as Record<string, unknown>;
  // An RSA key cannot be a did:key here, so the holder gets a did:jwk. Either way the
  // credential is bound to a key the wallet holds.
  check('RSA wallet is bound via did:jwk', String(injiSubject.id).startsWith('did:jwk:'));
  check('Inji-style credential verifies', await LdpIssuer.verify(injiVc, issuerPub));
  console.log('');

  // ---- The jwt_vc_json format still works, and still verifies -------------
  console.log('jwt_vc_json format (the offline / QR path):');
  const offerC = await vci.createOffer(residentId);
  const scannedC = JSON.parse(new URL(offerC.offerUri).searchParams.get('credential_offer')!);
  const tokenC = await vci.token({
    grantType: PRE_AUTHORIZED_CODE_GRANT,
    preAuthorizedCode: scannedC.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
    txCode: offerC.txCode,
  });
  const nonceC = (await vci.nonce()).c_nonce as string;
  const proofC = await makeProof({
    privateKey: walletA.privateKey,
    publicJwk: walletAJwk,
    alg: 'EdDSA',
    aud: ISSUER,
    nonce: nonceC,
  });
  const credResC = await vci.credential(`Bearer ${tokenC.access_token}`, {
    credential_configuration_id: 'NG_StateResidencyCredential_jwt_vc_json',
    proofs: { jwt: [proofC] },
  });
  const vcJwt = (credResC.credentials as { credential: string }[])[0].credential;
  check('jwt_vc_json is a compact JWT string', typeof vcJwt === 'string' && vcJwt.split('.').length === 3);

  const trust = new Map<string, TrustedIssuer>([
    [CONFIG.credential.issuerDid, { did: CONFIG.credential.issuerDid, publicJwk: key.publicJwk }],
  ]);
  const outcome = await new VcVerifier(trust).verify(vcJwt, { offline: true });
  check('jwt_vc_json verifies through the existing VcVerifier', outcome.valid);
  check('and it is bound to the same wallet key', outcome.subject?.id === expectedDid);
  console.log('');

  // ---- Attacks -----------------------------------------------------------
  console.log('Attacks that must fail:');

  // Replay a key proof: the nonce is single-use.
  await rejects('a replayed key proof (reused nonce) is rejected', 'invalid_nonce', async () => {
    const offerR = await vci.createOffer(residentId);
    const scannedR = JSON.parse(new URL(offerR.offerUri).searchParams.get('credential_offer')!);
    const tokR = await vci.token({
      grantType: PRE_AUTHORIZED_CODE_GRANT,
      preAuthorizedCode: scannedR.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
      txCode: offerR.txCode,
    });
    // proofA was already spent in Wallet A's request above.
    return vci.credential(`Bearer ${tokR.access_token}`, {
      credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
      proofs: { jwt: [proofA] },
    });
  });

  // Redeem the same pre-authorized code twice.
  await rejects('a reused pre-authorized code is rejected', 'invalid_grant', () =>
    vci.token({
      grantType: PRE_AUTHORIZED_CODE_GRANT,
      preAuthorizedCode: preAuthCode,
      txCode: offer.txCode,
    }),
  );

  // Wrong PIN.
  const offerP = await vci.createOffer(residentId);
  const scannedP = JSON.parse(new URL(offerP.offerUri).searchParams.get('credential_offer')!);
  const codeP: string = scannedP.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'];
  const wrongPin = offerP.txCode === '000000' ? '111111' : '000000';
  await rejects('a wrong tx_code is rejected', 'invalid_grant', () =>
    vci.token({ grantType: PRE_AUTHORIZED_CODE_GRANT, preAuthorizedCode: codeP, txCode: wrongPin }),
  );

  // PIN brute force is bounded.
  for (let i = 0; i < 5; i++) {
    await vci
      .token({ grantType: PRE_AUTHORIZED_CODE_GRANT, preAuthorizedCode: codeP, txCode: wrongPin })
      .catch(() => undefined);
  }
  await rejects('the offer locks after repeated wrong PINs', 'invalid_grant', () =>
    vci.token({
      grantType: PRE_AUTHORIZED_CODE_GRANT,
      preAuthorizedCode: codeP,
      txCode: offerP.txCode, // even the CORRECT pin must now fail
    }),
  );

  // A proof minted for a different audience must not be accepted here: this is what
  // stops a proof harvested by one issuer being replayed against another.
  const offerX = await vci.createOffer(residentId);
  const scannedX = JSON.parse(new URL(offerX.offerUri).searchParams.get('credential_offer')!);
  const tokX = await vci.token({
    grantType: PRE_AUTHORIZED_CODE_GRANT,
    preAuthorizedCode: scannedX.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
    txCode: offerX.txCode,
  });
  const nonceX = (await vci.nonce()).c_nonce as string;
  await rejects('a proof made out to another issuer is rejected', 'invalid_proof', async () => {
    const evil = await makeProof({
      privateKey: walletA.privateKey,
      publicJwk: walletAJwk,
      alg: 'EdDSA',
      aud: 'https://someone-elses-issuer.example',
      nonce: nonceX,
    });
    return vci.credential(`Bearer ${tokX.access_token}`, {
      credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
      proofs: { jwt: [evil] },
    });
  });

  // No proof at all: we must never mint an unbound credential.
  await rejects('a request with no key proof is refused', 'invalid_proof', () =>
    vci.credential(`Bearer ${tokX.access_token}`, {
      credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
    }),
  );

  // No access token.
  await rejects('an unauthenticated credential request is refused', 'invalid_token', () =>
    vci.credential(undefined, {
      credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
      proofs: { jwt: [proofA] },
    }),
  );

  // ---- Revocation still reaches wallet-held credentials ------------------
  console.log('');
  console.log('Revocation:');
  const record = await residents.findByResidentId(residentId);
  check(
    'every wallet-held credential shares the resident status index',
    // All three credentials above were minted for the same record, so one bit revokes all.
    record != null && typeof record.statusListIndex === 'number',
  );
  await residency.revoke(CONFIG, residentId);
  const list = await residents.loadStatusList('NG');
  check('revoking the resident flips the shared status bit', list.isRevoked(record!.statusListIndex));

  const revokedTrust = new Map<string, TrustedIssuer>([
    [
      CONFIG.credential.issuerDid,
      {
        did: CONFIG.credential.issuerDid,
        publicJwk: key.publicJwk,
        statusLists: { [`${ISSUER}/.well-known/status/ng.json`]: list },
      },
    ],
  ]);
  const after = await new VcVerifier(revokedTrust).verify(vcJwt, { offline: true });
  check('the wallet-held credential now verifies as REVOKED', !after.valid && after.reason === 'REVOKED');


  // ---- A strict profile: config actually narrows the surface -------------
  //
  // The defaults above are the widest possible surface, so that the hardest real wallet
  // (Inji) works out of the box. A deployment whose wallets have all moved to OpenID4VCI
  // 1.0 should be able to decline to pay for that width. This proves the config knobs are
  // load-bearing rather than decorative: turning them off must actually REJECT things.
  console.log('');
  console.log('A strict wallet profile (1.0 only, EdDSA only, ldp_vc only):');

  const STRICT: CountryConfig = parseCountryConfig({
    ...JSON.parse(JSON.stringify({
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
    })),
    wallet: {
      formats: ['ldp_vc'],
      proofAlgs: ['EdDSA'],
      compatibility: { draft13: false, cNonceInAccessToken: false },
      offer: { txCodeLength: 8, maxTxCodeAttempts: 3 },
    },
  });

  const strictResidents = new InMemoryStore();
  const strictResidency = new ResidencyService(
    new ProviderRegistry('test-pepper'),
    new VcIssuer(key),
    strictResidents,
    () => `${ISSUER}/.well-known/status/ng.json`,
    new LdpIssuer(key),
  );
  const strict = new Oid4vciService(
    { credentialIssuer: ISSUER },
    () => [STRICT],
    (cc) => (cc.toUpperCase() === 'NG' ? STRICT : undefined),
    strictResidency,
    strictResidents,
    new InMemoryOid4vciStore(),
    key,
  );

  const strictEnrolled = await strictResidency.issue(STRICT, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  if (strictEnrolled.status !== 'issued') throw new Error('strict enrollment failed');

  const strictMeta = strict.credentialIssuerMetadata();
  const strictConfigs = strictMeta.credential_configurations_supported as Record<string, any>;
  check(
    'metadata offers ONLY ldp_vc',
    'NG_StateResidencyCredential_ldp_vc' in strictConfigs &&
      !('NG_StateResidencyCredential_jwt_vc_json' in strictConfigs),
  );
  check(
    'metadata advertises ONLY EdDSA (RS256 is gone)',
    JSON.stringify(
      strictConfigs['NG_StateResidencyCredential_ldp_vc'].proof_types_supported.jwt
        .proof_signing_alg_values_supported,
    ) === '["EdDSA"]',
  );

  const strictOffer = await strict.createOffer(strictEnrolled.residentId);
  check('tx_code honours the configured length (8 digits)', strictOffer.txCode.length === 8);
  const strictScanned = JSON.parse(
    new URL(strictOffer.offerUri).searchParams.get('credential_offer')!,
  );
  check(
    'the offer advertises the configured tx_code length',
    strictScanned.grants[PRE_AUTHORIZED_CODE_GRANT].tx_code.length === 8,
  );

  const strictToken = await strict.token({
    grantType: PRE_AUTHORIZED_CODE_GRANT,
    preAuthorizedCode: strictScanned.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
    txCode: strictOffer.txCode,
  });

  // The non-standard Inji claims must be GONE, not merely ignored.
  const strictAt = JSON.parse(
    Buffer.from((strictToken.access_token as string).split('.')[1], 'base64url').toString(),
  );
  check(
    'the non-standard c_nonce/client_id claims are absent from the access token',
    strictAt.c_nonce === undefined && strictAt.client_id === undefined,
  );

  const strictNonce = (await strict.nonce()).c_nonce as string;

  // An RS256 proof -- which Inji would send -- must now be refused.
  await rejects('an RS256 key proof is rejected', 'invalid_proof', async () => {
    const rsaProof = await makeProof({
      privateKey: walletB.privateKey,
      publicJwk: walletBJwk,
      alg: 'RS256',
      aud: ISSUER,
      nonce: strictNonce,
    });
    return strict.credential(`Bearer ${strictToken.access_token}`, {
      credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
      proofs: { jwt: [rsaProof] },
    });
  });

  // A Draft 13 request must now be refused outright.
  await rejects('a Draft 13 request is rejected', 'invalid_credential_request', async () => {
    const p = await makeProof({
      privateKey: walletA.privateKey,
      publicJwk: walletAJwk,
      alg: 'EdDSA',
      aud: ISSUER,
      nonce: (await strict.nonce()).c_nonce as string,
    });
    return strict.credential(`Bearer ${strictToken.access_token}`, {
      format: 'ldp_vc',
      proof: { proof_type: 'jwt', jwt: p },
    });
  });

  // And a spec-current 1.0 wallet must still work perfectly.
  const strictOk = await strict.credential(`Bearer ${strictToken.access_token}`, {
    credential_configuration_id: 'NG_StateResidencyCredential_ldp_vc',
    proofs: {
      jwt: [
        await makeProof({
          privateKey: walletA.privateKey,
          publicJwk: walletAJwk,
          alg: 'EdDSA',
          aud: ISSUER,
          nonce: (await strict.nonce()).c_nonce as string,
        }),
      ],
    },
  });
  check('a spec-current 1.0 wallet still succeeds', Array.isArray(strictOk.credentials));

  console.log(`\n${pass} passed, ${fail} failed\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
