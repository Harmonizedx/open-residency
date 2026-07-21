/* eslint-disable no-console */
/**
 * OpenID4VP end-to-end check.
 *
 * A wallet obtains a residency credential (over OpenID4VCI), then presents it to a
 * relying party. This drives both sides: the relying party opens a request, the wallet
 * fetches and verifies the signed request object, builds a Verifiable Presentation, and
 * posts it; the relying party collects the verdict.
 *
 * Then it runs the attacks that a presentation -- as opposed to a bare credential -- is
 * supposed to stop. These are the ones that the old `POST /residency/verify` could not
 * catch, because it verified a credential without ever asking who was holding it:
 *
 *   - a STOLEN credential, presented by someone who does not hold its key
 *   - a REPLAYED presentation, posted a second time
 *   - a presentation captured by one verifier and REPLAYED AT ANOTHER
 *   - a presentation carrying a stale nonce
 *   - a REVOKED credential
 */
import { SignJWT, generateKeyPair, exportJWK, jwtVerify, KeyLike, JWK } from 'jose';
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
import { InMemoryOid4vpStore } from '../src/core/oid4vp/ports';
import { Oid4vpService } from '../src/core/oid4vp/oid4vp-service';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../src/core/oid4vp/vp-verifier';
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

const BASE = 'https://id.katsina.gov.ng';
const ISSUER_DID = 'did:web:id.katsina.gov.ng';
const STATUS_URL = `${BASE}/.well-known/status/ng.json`;

const CONFIG: CountryConfig = parseCountryConfig({
  countryCode: 'NG',
  countryName: 'Nigeria',
  foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
  residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
  credential: {
    issuerDid: ISSUER_DID,
    issuerName: 'Katsina State Residency Authority',
    type: 'StateResidencyCredential',
    validityDays: 1095,
    context: ['https://www.w3.org/ns/credentials/v2'],
  },
  subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
});

/** A wallet builds a Verifiable Presentation over the credential it holds. */
async function buildVp(opts: {
  privateKey: KeyLike;
  holderDid: string;
  credential: string | LdpCredential;
  nonce: string;
  audience: string;
}): Promise<string> {
  return new SignJWT({
    nonce: opts.nonce,
    vp: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: opts.holderDid,
      verifiableCredential: [opts.credential],
    },
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: `${opts.holderDid}#0`, typ: 'JWT' })
    .setIssuer(opts.holderDid)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(opts.privateKey);
}

async function main() {
  console.log('\n== OpenID4VP presentation: wallet and relying party, end to end ==\n');

  // ---- The deployment ----------------------------------------------------
  const key = await KeyStore.generate('issuer-key-1');
  const residents = new InMemoryStore();
  const residency = new ResidencyService(
    new ProviderRegistry('test-pepper'),
    new VcIssuer(key),
    residents,
    () => STATUS_URL,
    new LdpIssuer(key),
  );
  const vci = new Oid4vciService(
    { credentialIssuer: BASE },
    () => [CONFIG],
    (cc) => (cc.toUpperCase() === 'NG' ? CONFIG : undefined),
    residency,
    residents,
    new InMemoryOid4vciStore(),
    key,
  );

  const trust = new Map<string, TrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicJwks: [key.publicJwk], statusLists: {} }],
  ]);
  const vcVerifier = new VcVerifier(trust);
  const ldpTrust = new Map<string, VpTrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicKeyObjects: [keyObjectFromJwk(key.publicJwk)] }],
  ]);
  const vpVerifier = new VpVerifier(vcVerifier, ldpTrust);
  const vpStore = new InMemoryOid4vpStore();
  const vp = new Oid4vpService(
    {
      baseUrl: BASE,
      clientId: ISSUER_DID,
      clientName: 'Katsina General Hospital',
      requestTtlSeconds: CONFIG.presentation.requestTtlSeconds,
      query: CONFIG.presentation.query,
    },
    vpStore,
    () => vpVerifier,
    key,
  );

  /** Obtain a wallet-bound credential over OpenID4VCI. */
  async function issueTo(
    walletKey: { privateKey: KeyLike; publicJwk: JWK },
    residentId: string,
    format: 'ldp_vc' | 'jwt_vc_json',
  ): Promise<string | LdpCredential> {
    const offer = await vci.createOffer(residentId);
    const scanned = JSON.parse(new URL(offer.offerUri).searchParams.get('credential_offer')!);
    const tok = await vci.token({
      grantType: PRE_AUTHORIZED_CODE_GRANT,
      preAuthorizedCode: scanned.grants[PRE_AUTHORIZED_CODE_GRANT]['pre-authorized_code'],
      txCode: offer.txCode,
    });
    const nonce = (await vci.nonce()).c_nonce as string;
    const proof = await new SignJWT({ nonce })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'openid4vci-proof+jwt',
        jwk: walletKey.publicJwk as any,
      })
      .setAudience(BASE)
      .setIssuedAt()
      .sign(walletKey.privateKey);
    const res = await vci.credential(`Bearer ${tok.access_token}`, {
      credential_configuration_id: `NG_StateResidencyCredential_${format}`,
      proofs: { jwt: [proof] },
    });
    return (res.credentials as { credential: string | LdpCredential }[])[0].credential;
  }

  // ---- Amina enrolls and loads her wallet --------------------------------
  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' }, // MOCK verifies even last digit
  });
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const residentId = enrolled.residentId;

  const aminaKp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const amina = { privateKey: aminaKp.privateKey, publicJwk: await exportJWK(aminaKp.publicKey) };
  const aminaDid = didKeyFromJwk(amina.publicJwk);
  const aminaLdpVc = (await issueTo(amina, residentId, 'ldp_vc')) as LdpCredential;
  const aminaJwtVc = (await issueTo(amina, residentId, 'jwt_vc_json')) as string;

  /** What the controller does before every verification: refresh the revocation snapshot. */
  async function syncStatusList() {
    trust.get(ISSUER_DID)!.statusLists = { [STATUS_URL]: await residents.loadStatusList('NG') };
  }
  await syncStatusList();

  console.log('Setup:');
  check('Amina holds a wallet-bound ldp_vc', (aminaLdpVc.credentialSubject as any).id === aminaDid);
  check('Amina also holds a wallet-bound jwt_vc_json', typeof aminaJwtVc === 'string');
  console.log('');

  // ---- The happy path ----------------------------------------------------
  console.log('A hospital asks Amina to prove residency:');
  const request = await vp.createRequest({
    purpose: 'Confirm state residency for subsidised care',
    reference: 'visit-4471',
  });
  check('request URI uses the openid4vp scheme', request.requestUri.startsWith('openid4vp://'));

  // The wallet dereferences request_uri and CHECKS THE SIGNATURE before showing the
  // citizen a consent prompt. An unsigned request would let anything that can display a
  // QR impersonate a hospital.
  const requestJwt = await vp.requestObject(request.requestId);
  const verifiedRequest = await jwtVerify(requestJwt, key.publicKey, { issuer: ISSUER_DID });
  const rp = verifiedRequest.payload as Record<string, any>;
  check('the wallet can verify who is asking (request object is signed)', true);
  check('request object names the response endpoint', typeof rp.response_uri === 'string');
  check('request object uses direct_post', rp.response_mode === 'direct_post');
  check('request object carries a nonce', typeof rp.nonce === 'string');
  check('request offers DCQL (OpenID4VP 1.0)', rp.dcql_query != null);
  check('request also offers presentation_definition (wallets on PEX)', rp.presentation_definition != null);
  check(
    'the citizen is told who is asking and why',
    rp.client_metadata?.client_name === 'Katsina General Hospital' &&
      typeof rp.client_metadata?.purpose === 'string',
  );

  // Amina consents; the wallet presents.
  const presentation = await buildVp({
    privateKey: amina.privateKey,
    holderDid: aminaDid,
    credential: aminaLdpVc,
    nonce: rp.nonce,
    audience: rp.client_id,
  });
  await vp.handleResponse(request.requestId, { vp_token: presentation, state: request.requestId });

  const result = await vp.result(request.requestId);
  const outcome = result.outcome as Record<string, any>;
  check('the hospital sees a fulfilled request', result.status === 'fulfilled');
  check('the presentation verifies', outcome.valid === true);
  check('the holder is identified', outcome.holderDid === aminaDid);
  check('revocation was actually checked', outcome.checkedRevocation === true);
  check('the hospital gets the residency claims it asked for', outcome.claims.residentId === residentId);
  check('and the subnational unit', outcome.claims.subnationalUnit?.name === 'Katsina');
  check('the relying party reference is echoed back', result.reference === 'visit-4471');

  // Data minimisation: the credential carries the tokenized national-ID reference. A
  // hospital confirming residency has no business receiving it, and it is precisely the
  // field the whole tokenization design exists to protect.
  const released = JSON.stringify(outcome.claims);
  check('the national-ID reference is NOT released to the verifier', !released.includes('subjectRef'));
  check('the date of birth is NOT released either', !released.includes('dateOfBirth'));
  console.log('');

  // ---- The jwt_vc_json format presents too --------------------------------
  console.log('The same works for the VC-JWT (offline/QR) format:');
  const reqJwt = await vp.createRequest({ purpose: 'Residency check' });
  const rpJwt = (await jwtVerify(await vp.requestObject(reqJwt.requestId), key.publicKey))
    .payload as Record<string, any>;
  await vp.handleResponse(reqJwt.requestId, {
    vp_token: await buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaJwtVc,
      nonce: rpJwt.nonce,
      audience: rpJwt.client_id,
    }),
  });
  const jwtOutcome = (await vp.result(reqJwt.requestId)).outcome as Record<string, any>;
  check('a VC-JWT presentation verifies', jwtOutcome.valid === true);
  console.log('');

  // ---- Attacks -----------------------------------------------------------
  console.log('Attacks that the OLD /residency/verify could not catch:');

  /** Run a presentation and return why it was rejected. */
  async function presentAndGetReason(build: (rp: Record<string, any>) => Promise<string>) {
    const req = await vp.createRequest({ purpose: 'Residency check' });
    const obj = (await jwtVerify(await vp.requestObject(req.requestId), key.publicKey))
      .payload as Record<string, any>;
    await vp.handleResponse(req.requestId, { vp_token: await build(obj) }).catch(() => undefined);
    const out = (await vp.result(req.requestId)).outcome as Record<string, any> | undefined;
    return out?.reason;
  }

  // THE BIG ONE. Mallory steals a copy of Amina's credential -- exactly what a leaked
  // VC-JWT is -- and presents it under her own key. The old endpoint would have said
  // "valid": the credential is genuine, unexpired, unrevoked. The presentation must not.
  const malloryKp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const malloryJwk = await exportJWK(malloryKp.publicKey);
  const malloryDid = didKeyFromJwk(malloryJwk);
  const stolenReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: malloryKp.privateKey,
      holderDid: malloryDid, // her key ...
      credential: aminaLdpVc, // ... but Amina's credential
      nonce: rp.nonce,
      audience: rp.client_id,
    }),
  );
  check("a STOLEN credential presented under someone else's key is rejected", stolenReason === 'HOLDER_NOT_SUBJECT', `got ${stolenReason}`);

  // A stale nonce: a presentation built for one request, posted against another.
  const staleReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaLdpVc,
      nonce: 'a-nonce-we-never-issued',
      audience: rp.client_id,
    }),
  );
  check('a presentation with a stale nonce is rejected', staleReason === 'NONCE_MISMATCH', `got ${staleReason}`);

  // Cross-verifier replay: a shop captures Amina's presentation and replays it at a
  // hospital. The audience binding is what stops this.
  const wrongAudReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaLdpVc,
      nonce: rp.nonce,
      audience: 'did:web:some-other-verifier.example',
    }),
  );
  check('a presentation made out to another verifier is rejected', wrongAudReason === 'WRONG_AUDIENCE', `got ${wrongAudReason}`);

  // Replay of a presentation that already succeeded, against its own request.
  const replayReq = await vp.createRequest({ purpose: 'Residency check' });
  const replayRp = (await jwtVerify(await vp.requestObject(replayReq.requestId), key.publicKey))
    .payload as Record<string, any>;
  const goodVp = await buildVp({
    privateKey: amina.privateKey,
    holderDid: aminaDid,
    credential: aminaLdpVc,
    nonce: replayRp.nonce,
    audience: replayRp.client_id,
  });
  await vp.handleResponse(replayReq.requestId, { vp_token: goodVp });
  let replayRejected = false;
  try {
    await vp.handleResponse(replayReq.requestId, { vp_token: goodVp });
  } catch {
    replayRejected = true;
  }
  check('a REPLAYED presentation is rejected (requests are single-use)', replayRejected);

  // A tampered credential inside an otherwise valid presentation.
  const tamperedVc = JSON.parse(JSON.stringify(aminaLdpVc)) as LdpCredential;
  (tamperedVc.credentialSubject as any).subnationalUnit.name = 'Lagos';
  const tamperReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: tamperedVc,
      nonce: rp.nonce,
      audience: rp.client_id,
    }),
  );
  check('a tampered credential inside a valid presentation is rejected', tamperReason === 'BAD_SIGNATURE', `got ${tamperReason}`);
  console.log('');

  // ---- Revocation reaches presentations ----------------------------------
  console.log('Revocation:');
  await residency.revoke(CONFIG, residentId);
  await syncStatusList(); // as the controller does before each response

  const revokedReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaLdpVc,
      nonce: rp.nonce,
      audience: rp.client_id,
    }),
  );
  check('a REVOKED credential cannot be presented (ldp_vc)', revokedReason === 'REVOKED', `got ${revokedReason}`);

  const revokedJwtReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaJwtVc,
      nonce: rp.nonce,
      audience: rp.client_id,
    }),
  );
  check('a REVOKED credential cannot be presented (jwt_vc_json)', revokedJwtReason === 'REVOKED', `got ${revokedJwtReason}`);

  // Fail closed: if the verifier has NO status list to check against, an online
  // presentation must be refused rather than accepted with a quiet "we didn't check"
  // flag that no relying party will ever read.
  console.log('');
  console.log('Fail-closed behaviour:');
  trust.get(ISSUER_DID)!.statusLists = {};
  const unknownReason = await presentAndGetReason((rp) =>
    buildVp({
      privateKey: amina.privateKey,
      holderDid: aminaDid,
      credential: aminaJwtVc,
      nonce: rp.nonce,
      audience: rp.client_id,
    }),
  );
  check(
    'a presentation is REFUSED when revocation cannot be checked',
    unknownReason === 'REVOCATION_UNCHECKABLE',
    `got ${unknownReason}`,
  );

  console.log(`\n${pass} passed, ${fail} failed\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
