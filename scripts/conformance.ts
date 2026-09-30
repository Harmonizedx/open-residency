// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * W3C conformance checks, run in CI on every pull request.
 *
 * The README claims conformance with the Verifiable Credentials Data Model. Until now
 * nothing tested that claim, which for a Digital Public Good whose entire value
 * proposition is standards conformance is a liability -- and reviewers are entitled to
 * ask us to prove it.
 *
 * This asserts the normative MUSTs of:
 *   - VC Data Model 2.0            https://www.w3.org/TR/vc-data-model-2.0/
 *   - Bitstring Status List 1.0    https://www.w3.org/TR/vc-bitstring-status-list/
 *   - VC Data Integrity (eddsa-rdfc-2022)
 *
 * against credentials we actually issue, in both formats.
 *
 * It is NOT a substitute for the official W3C suite, and does not pretend to be. That
 * suite drives an implementation over the VC-API and is the real authority; see
 * test/w3c/README.md for how to run it. This is the fast, hermetic, no-network check that
 * can gate every commit -- and it is the one that caught our encodedList bug.
 */
import { gunzipSync } from 'node:zlib';
import { createPublicKey } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { StatusList, unsignedStatusListCredential } from '../src/core/credentials/status-list';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { buildDidWebDocument, didKeyFromJwk, didKeyToJwk } from '../src/core/credentials/did';
import {
  validateCredentialShape,
  validatePresentationShape,
  validateStatusEntry,
  validateStatusListCredential,
} from '../src/core/credentials/data-model';
import { pinnedResourceBytes } from '../src/core/credentials/jsonld/document-loader';

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

/** A credential that violates a MUST must be REJECTED. Conformance cuts both ways. */
function mustReject(name: string, credential: Record<string, unknown>, expected: RegExp) {
  const errors = validateCredentialShape(credential);
  const matched = errors.some((e) => expected.test(e));
  check(name, matched, matched ? undefined : `errors were: ${JSON.stringify(errors)}`);
}

const BASE = 'https://id.katsina.gov.ng';
const STATUS_URL = `${BASE}/.well-known/status/ng.json`;

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
});

/** A minimal, valid VC 2.0 credential, used as the base for the negative tests. */
function validCredential(): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:6e1f6d1e-0000-4000-8000-000000000000',
    type: ['VerifiableCredential', 'StateResidencyCredential'],
    issuer: { id: 'did:web:id.katsina.gov.ng', name: 'Katsina' },
    validFrom: '2026-07-14T00:00:00Z',
    credentialSubject: { id: 'did:key:z6Mk', residentId: 'KT-0001' },
  };
}

async function main() {
  console.log('\n== W3C conformance ==\n');

  const key = await KeyStore.generate('issuer-key-1');
  const residents = new InMemoryStore();
  const ldpIssuer = new LdpIssuer(key);
  const residency = new ResidencyService(
    new ProviderRegistry('test-pepper'),
    new VcIssuer(key),
    residents,
    () => STATUS_URL,
    ldpIssuer,
  );

  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const record = (await residents.findByResidentId(enrolled.residentId))!;

  const holderKey = await KeyStore.generate('holder');
  const holderDid = didKeyFromJwk(holderKey.publicJwk);

  const ldp = (await residency.mintForHolder(CONFIG, record, holderDid, 'ldp_vc'))
    .credential as LdpCredential;
  const jwt = (await residency.mintForHolder(CONFIG, record, holderDid, 'jwt_vc_json'))
    .credential as string;

  // ---- VC Data Model 2.0, against credentials we really issue ------------
  console.log('VC Data Model 2.0 -- the credentials we issue:');

  const ldpErrors = validateCredentialShape(ldp);
  check('an issued ldp_vc satisfies the data model', ldpErrors.length === 0, JSON.stringify(ldpErrors));

  // A VC-JWT carries the credential in the `vc` claim.
  const vcFromJwt = decodeJwt(jwt).vc as Record<string, unknown>;
  const jwtErrors = validateCredentialShape(vcFromJwt);
  check('an issued jwt_vc_json satisfies the data model', jwtErrors.length === 0, JSON.stringify(jwtErrors));

  check(
    'validFrom / validUntil are dateTimeStamps (timezone is mandatory)',
    typeof ldp.validFrom === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(ldp.validFrom as string),
  );
  check(
    'the two formats carry identical subject claims',
    JSON.stringify((ldp.credentialSubject as any).residentId) ===
      JSON.stringify((vcFromJwt.credentialSubject as any).residentId),
  );

  // VC-JWT profile: the registered claims must mirror the credential.
  const payload = decodeJwt(jwt);
  const header = decodeProtectedHeader(jwt);
  check('VC-JWT alg is EdDSA', header.alg === 'EdDSA');
  check('VC-JWT iss mirrors the credential issuer', payload.iss === CONFIG.credential.issuerDid);
  check('VC-JWT sub mirrors the credential subject', payload.sub === holderDid);
  check('VC-JWT jti mirrors the credential id', payload.jti === vcFromJwt.id);
  check('VC-JWT exp is set', typeof payload.exp === 'number');
  console.log('');

  // ---- The data model MUSTs are actually ENFORCED ------------------------
  // Conformance is not only "we emit valid credentials"; it is also "we reject invalid
  // ones". The official suite tests each MUST by sending a violation and expecting a 400,
  // so every rule we do not enforce is a test we fail.
  console.log('VC Data Model 2.0 -- violations are rejected:');

  check('a valid credential passes cleanly', validateCredentialShape(validCredential()).length === 0);

  mustReject('@context is required', { ...validCredential(), '@context': undefined }, /@context/);
  mustReject(
    'the VC v2 context must come FIRST',
    { ...validCredential(), '@context': ['https://example.org/other', 'https://www.w3.org/ns/credentials/v2'] },
    /first @context/,
  );
  mustReject(
    'type must include VerifiableCredential',
    { ...validCredential(), type: ['StateResidencyCredential'] },
    /VerifiableCredential/,
  );
  mustReject('credentialSubject is required', { ...validCredential(), credentialSubject: undefined }, /credentialSubject/);
  mustReject('credentialSubject must not be empty', { ...validCredential(), credentialSubject: {} }, /empty/);
  mustReject('issuer is required', { ...validCredential(), issuer: undefined }, /issuer/);
  mustReject('issuer must be a URI', { ...validCredential(), issuer: 'not a uri' }, /issuer id must be a URI/);
  mustReject('id must be a URI', { ...validCredential(), id: 'not-a-uri' }, /id must be a URI/);
  mustReject('id must not be an array', { ...validCredential(), id: ['urn:uuid:a', 'urn:uuid:b'] }, /array/);
  // The subtle one: a dateTime without a timezone is NOT a dateTimeStamp.
  mustReject(
    'validFrom without a timezone is rejected',
    { ...validCredential(), validFrom: '2026-07-14T00:00:00' },
    /dateTimeStamp/,
  );
  mustReject(
    'credentialStatus without a type is rejected',
    { ...validCredential(), credentialStatus: { id: 'https://x.test/1#0' } },
    /credentialStatus must have a type/,
  );
  console.log('');

  // ---- Typed sub-objects -------------------------------------------------
  // An untyped sub-object is one a consumer cannot act on: an untyped refreshService is
  // an endpoint of unknown protocol, an untyped termsOfUse a policy nobody can evaluate.
  console.log('Sub-objects MUST specify a type:');

  for (const field of ['termsOfUse', 'evidence', 'refreshService', 'credentialSchema'] as const) {
    mustReject(
      `${field} without a type is rejected`,
      { ...validCredential(), [field]: { id: 'https://x.test/thing' } },
      new RegExp(`${field} must have a type`),
    );
    check(
      `${field} with a type is accepted`,
      validateCredentialShape({
        ...validCredential(),
        [field]: { id: 'https://x.test/thing', type: 'ExampleType' },
      }).length === 0,
    );
  }
  mustReject(
    'a proof without a type is rejected',
    { ...validCredential(), proof: { proofValue: 'z1' } },
    /proof must have a type/,
  );
  mustReject(
    'credentialSchema without an id is rejected',
    { ...validCredential(), credentialSchema: { type: 'JsonSchema' } },
    /credentialSchema must have an id/,
  );
  // A set of subjects where one member is empty: as meaningless as a single empty
  // subject, and easier to miss.
  mustReject(
    'a credentialSubject set containing an empty member is rejected',
    { ...validCredential(), credentialSubject: [{ id: 'did:key:z6Mk' }, {}] },
    /every credentialSubject must be a non-empty object/,
  );
  console.log('');

  // ---- Integrity of related resources (VCDM 2.0 s5.3) --------------------
  // The digest checks run against the PINNED bytes, so they need no network -- the same
  // terms the JSON-LD loader works on. A resource we do not hold is left unverified
  // rather than fetched or rejected.
  console.log('relatedResource integrity:');

  const V2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';
  const resourceOptions = { resolveResourceBytes: pinnedResourceBytes };
  const goodSri = 'sha384-l/HrjlBCNWyAX91hr6LFV2Y3heB5Tcr6IeE4/Tje8YyzYBM8IhqjHWiWpr8+ZbYU';
  const goodMultibase = 'uWZVc7WaX1h4D8rJVb-vlMIqxaEKEb1tYbX8fet7JJzQ';

  const relatedRejects = (name: string, relatedResource: unknown, expected: RegExp) => {
    const errors = validateCredentialShape(
      { ...validCredential(), relatedResource } as Record<string, unknown>,
      resourceOptions,
    );
    check(name, errors.some((e) => expected.test(e)), `errors were: ${JSON.stringify(errors)}`);
  };

  check(
    'a correct digestSRI over a pinned resource is accepted',
    validateCredentialShape(
      { ...validCredential(), relatedResource: { id: V2_CONTEXT_URL, digestSRI: goodSri } },
      resourceOptions,
    ).length === 0,
  );
  check(
    'a correct digestMultibase over a pinned resource is accepted',
    validateCredentialShape(
      { ...validCredential(), relatedResource: { id: V2_CONTEXT_URL, digestMultibase: goodMultibase } },
      resourceOptions,
    ).length === 0,
  );
  relatedRejects('an array of strings is rejected', [V2_CONTEXT_URL], /must be one or more objects/);
  relatedRejects('a resource with no id is rejected', [{ digestSRI: goodSri }], /must have an id/);
  relatedRejects(
    'a duplicate id is rejected',
    [
      { id: V2_CONTEXT_URL, digestSRI: goodSri },
      { id: V2_CONTEXT_URL, digestMultibase: goodMultibase },
    ],
    /must be unique/,
  );
  relatedRejects('a resource with no digest is rejected', [{ id: V2_CONTEXT_URL }], /at least a digest/);
  // The one that actually matters: a stated digest that does not match the bytes it names
  // looks like an integrity guarantee while providing none.
  relatedRejects(
    'a digestSRI that does not match the resource is rejected',
    [{ id: V2_CONTEXT_URL, digestSRI: 'sha384-' + 'A'.repeat(64) }],
    /digestSRI does not match/,
  );
  relatedRejects(
    'a digestMultibase that does not match the resource is rejected',
    [{ id: V2_CONTEXT_URL, digestMultibase: 'uM4RgWQc3RUDtjJCSgTJtTfvpZ7SPEg_LNO0ESlovQC0' }],
    /digestMultibase does not match/,
  );
  check(
    'an unpinned resource is left unverified rather than refused',
    validateCredentialShape(
      { ...validCredential(), relatedResource: { id: 'https://example.test/x', digestSRI: goodSri } },
      resourceOptions,
    ).length === 0,
  );
  console.log('');

  // ---- Presentations ------------------------------------------------------
  console.log('Verifiable presentations:');

  const validPresentation = () => ({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
  });
  const vpRejects = (name: string, vp: Record<string, unknown>, expected: RegExp) => {
    const errors = validatePresentationShape(vp);
    check(name, errors.some((e) => expected.test(e)), `errors were: ${JSON.stringify(errors)}`);
  };

  check('a valid presentation passes cleanly', validatePresentationShape(validPresentation()).length === 0);
  vpRejects(
    'a presentation without @context is rejected',
    { type: ['VerifiablePresentation'] },
    /@context is required/,
  );
  vpRejects(
    'a presentation with the v2 context out of first place is rejected',
    { ...validPresentation(), '@context': ['https://example.org/other', 'https://www.w3.org/ns/credentials/v2'] },
    /first @context/,
  );
  vpRejects(
    'a presentation with an unprocessable @context entry is rejected',
    { ...validPresentation(), '@context': ['https://www.w3.org/ns/credentials/v2', 'not a url'] },
    /is not a URL/,
  );
  vpRejects(
    'a presentation without the VerifiablePresentation type is rejected',
    { ...validPresentation(), type: ['SomethingElse'] },
    /VerifiablePresentation/,
  );
  console.log('');

  // ---- Language and base direction (VCDM 2.0 s11.1) ----------------------
  // These MUST be signable. `@direction` has no home in the RDF unless the canonicalizer
  // is told to carry it, and safe mode then refuses the document rather than dropping the
  // direction silently -- so getting this wrong makes a spec-VALID credential unissuable.
  console.log('Language value objects:');

  // Only terms the pinned v2 context defines, so that a safe-mode failure here can mean
  // one thing only: the base direction was dropped. `validCredential()` carries residency
  // terms and is deliberately NOT used -- it is unsignable against the bare v2 context,
  // which is safe mode working correctly and would mask what this is testing.
  const languageValue = { '@value': 'Katsina State Residency', '@language': 'en', '@direction': 'ltr' };
  for (const field of ['name', 'description'] as const) {
    const withLanguage: Record<string, unknown> = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: CONFIG.credential.issuerDid,
      credentialSubject: { id: 'did:key:z6Mk' },
      [field]: languageValue,
    };
    check(
      `${field} as a language value object passes the data model`,
      validateCredentialShape(withLanguage).length === 0,
    );
    let signingError: string | undefined;
    try {
      await ldpIssuer.sign(withLanguage, CONFIG.credential.issuerDid);
    } catch (e) {
      signingError = e instanceof Error ? e.message : String(e);
    }
    check(`${field} as a language value object can be signed`, signingError === undefined, signingError);
  }
  console.log('');

  // ---- Bitstring Status List 1.0 -----------------------------------------
  console.log('Bitstring Status List v1.0:');

  const entry = ldp.credentialStatus as Record<string, unknown>;
  const entryErrors = validateStatusEntry(entry);
  check('the credentialStatus entry conforms', entryErrors.length === 0, JSON.stringify(entryErrors));
  check('statusListIndex is a STRING, not a number', typeof entry.statusListIndex === 'string');

  const list = await residents.loadStatusList('NG');
  const statusCredential = unsignedStatusListCredential({
    id: STATUS_URL,
    issuerDid: CONFIG.credential.issuerDid,
    list,
  });
  const statusErrors = validateStatusListCredential(statusCredential);
  check('the published status list credential conforms', statusErrors.length === 0, JSON.stringify(statusErrors));

  // The bug this suite was written to catch. The spec requires MULTIBASE base64url --
  // a leading 'u'. We were emitting bare base64url, which a strict verifier would decode
  // as garbage, reading the 'H' of the GZIP magic as the base identifier.
  const encoded = (statusCredential.credentialSubject as any).encodedList as string;
  check("encodedList is multibase base64url (leading 'u')", encoded.startsWith('u'), `got: ${encoded.slice(0, 8)}`);

  // And it must still be GZIP under that prefix.
  const raw = gunzipSync(Buffer.from(encoded.slice(1), 'base64url'));
  check('encodedList decodes to a GZIP bitstring', raw.length > 0);
  check(
    'the bitstring meets the 131,072-bit minimum',
    raw.length * 8 >= 131072,
    `got ${raw.length * 8} bits`,
  );

  // Round-trip: encode -> decode -> the same bits.
  const revokedIndex = record.statusListIndex;
  list.set(revokedIndex, true);
  const roundTripped = StatusList.fromEncoded(list.encode());
  check('a revoked bit survives an encode/decode round trip', roundTripped.isRevoked(revokedIndex));
  check('an unrelated bit stays unset', !roundTripped.isRevoked(revokedIndex + 1));

  // Backwards compatibility: a list published by an older deployment, without the
  // multibase prefix, must still decode. Revocation data that silently stops loading is
  // revocation that stops being enforced.
  const legacy = list.encode().slice(1); // strip the 'u', as the old code emitted
  const fromLegacy = StatusList.fromEncoded(legacy);
  check('a legacy (pre-multibase) status list still decodes', fromLegacy.isRevoked(revokedIndex));
  console.log('');

  // ---- Data Integrity ----------------------------------------------------
  console.log('VC Data Integrity (eddsa-rdfc-2022):');

  const proof = ldp.proof!;
  check('proof type is DataIntegrityProof', proof.type === 'DataIntegrityProof');
  check('cryptosuite is eddsa-rdfc-2022', proof.cryptosuite === 'eddsa-rdfc-2022');
  check('proofPurpose is assertionMethod', proof.proofPurpose === 'assertionMethod');
  check('created is a dateTimeStamp', /(?:Z|[+-]\d{2}:\d{2})$/.test(proof.created));
  check("proofValue is multibase base58btc (leading 'z')", proof.proofValue.startsWith('z'));

  const issuerPub = createPublicKey({ key: key.publicJwk as any, format: 'jwk' });
  check('the proof verifies', await LdpIssuer.verify(ldp, issuerPub));

  // #27: the PUBLISHED STATUS LIST must itself be signed and verifiable. A verifier syncs
  // this snapshot and then checks revocation offline against it; if the cached artifact
  // isn't self-authenticating, the verifier is trusting TLS at fetch time and nothing
  // afterwards. Sign the same envelope the delivery layer publishes, and prove it verifies.
  const signedStatus = await ldpIssuer.sign(statusCredential, CONFIG.credential.issuerDid);
  check('the published status list carries a proof', !!signedStatus.proof);
  check('the status list proof verifies', await LdpIssuer.verify(signedStatus, issuerPub));
  const tamperedStatus = JSON.parse(JSON.stringify(signedStatus)) as LdpCredential;
  (tamperedStatus.credentialSubject as Record<string, unknown>).encodedList = 'uH4sICORRUPTED';
  check(
    'a tampered status list does NOT verify',
    !(await LdpIssuer.verify(tamperedStatus, issuerPub)),
  );

  const tampered = JSON.parse(JSON.stringify(ldp)) as LdpCredential;
  (tampered.credentialSubject as any).residentId = 'KT-FORGED';
  check('a tampered credential does NOT verify', !(await LdpIssuer.verify(tampered, issuerPub)));

  // The verification method the proof names must actually resolve in the DID document.
  // A proof pointing at a key nobody can find is unverifiable, however well-formed.
  const didDoc = buildDidWebDocument(CONFIG.credential.issuerDid, key.publicJwk) as any;
  const methods: any[] = didDoc.verificationMethod;
  check(
    'the proof verificationMethod resolves in the DID document',
    methods.some((m) => m.id === proof.verificationMethod),
    `proof names ${proof.verificationMethod}`,
  );
  check(
    'the DID document publishes a Multikey (required by this cryptosuite)',
    methods.some((m) => m.type === 'Multikey' && typeof m.publicKeyMultibase === 'string'),
  );
  check(
    'the status list proof verificationMethod also resolves in the DID document',
    methods.some((m) => m.id === (signedStatus.proof as { verificationMethod?: string }).verificationMethod),
  );
  console.log('');

  // ---- did:key round trip ------------------------------------------------
  console.log('did:key:');
  const resolved = didKeyToJwk(holderDid);
  check('a did:key resolves back to the same public key', resolved.x === holderKey.publicJwk.x);
  check("did:key uses the Ed25519 multicodec (z6Mk prefix)", holderDid.startsWith('did:key:z6Mk'));

  console.log(`\n${pass} passed, ${fail} failed\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
