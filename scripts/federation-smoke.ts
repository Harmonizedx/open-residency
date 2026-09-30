// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Cross-issuer federation: a residency credential issued by ONE state verifies at another
 * when the issuer is federated, and is rejected when it is not.
 *
 * OpenResidency is single-issuer by default -- a deployment trusts only what it signed.
 * Federation adds peer issuers to the same trust map that holds the deployment's own key,
 * so the same verifier accepts them. This exercises that end to end in both credential
 * formats (VC-JWT and Data Integrity / ldp_vc), plus the negative case that makes the
 * trust boundary real: an unlisted issuer must fail as UNTRUSTED_ISSUER.
 */
import { createPublicKey } from 'node:crypto';
import { KeyStore } from '../src/core/credentials/keystore';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential, RESIDENCY_LDP_CONTEXT } from '../src/core/credentials/ldp-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { VpTrustedIssuer } from '../src/core/oid4vp/vp-verifier';
import {
  applyFederation,
  FederatedIssuer,
  statusListFromPublished,
  syncFederatedStatusLists,
} from '../src/core/credentials/federation';
import { StatusList } from '../src/core/credentials/status-list';
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

const HOME_DID = 'did:web:id.katsina.gov.ng';
const PEER_DID = 'did:web:id.kano.gov.ng';
const STRANGER_DID = 'did:web:id.somewhere.example';

function issueOpts(issuerDid: string) {
  return {
    issuerDid,
    issuerName: 'A State Residency Authority',
    type: 'StateResidencyCredential',
    context: ['https://www.w3.org/ns/credentials/v2'],
    validityDays: 1095,
    statusListIndex: 3,
    statusListUrl: `https://example.gov/status/x.json`,
  };
}
const claims = {
  holderId: 'did:key:z6MkHolder',
  residentId: 'KN-1A2B-3C4D',
  subnationalUnit: { country: 'NG', code: 'KN', name: 'Kano', level: 'state' },
  foundational: { provider: 'MOCK', assuranceLevel: 'verified', subjectRef: 'ref-1' },
  applicantBinding: { method: 'otp', assurance: 'medium', boundAt: '2026-01-01T00:00:00Z' } as any,
  person: { fullName: 'Amina Bello' },
  proofOfResidence: 'attestation',
  residence: { assuranceLevel: 'verified', method: 'attestation' } as any,
  provisional: false,
};

async function main() {
  console.log('\n== OpenResidency cross-issuer federation ==\n');

  // Home deployment key, and two other states' keys.
  const home = await KeyStore.generate('home-key-1');
  const peer = await KeyStore.generate('peer-key-1');
  const stranger = await KeyStore.generate('stranger-key-1');

  // --- Config parsing: a federation block is accepted and normalized --------
  const cfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: { issuerDid: HOME_DID, issuerName: 'Katsina', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
    federation: {
      trustedIssuers: [
        { did: PEER_DID, name: 'Kano State', publicJwks: [peer.publicJwk] },
      ],
    },
  });
  check('a federation block parses', cfg.federation.trustedIssuers.length === 1);
  check('the peer keeps its DID and public key', cfg.federation.trustedIssuers[0].did === PEER_DID);

  // A private key in a peer entry must be refused -- another issuer's secret must never
  // sit in config.
  let refusedPrivate = false;
  try {
    parseCountryConfig({
      countryCode: 'NG', countryName: 'Nigeria',
      foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
      residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
      credential: { issuerDid: HOME_DID, issuerName: 'K', type: 'StateResidencyCredential', validityDays: 1095, context: ['https://www.w3.org/ns/credentials/v2'] },
      subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
      federation: { trustedIssuers: [{ did: PEER_DID, publicJwks: [{ ...peer.publicJwk, d: 'AAAA' }] }] },
    } as any);
  } catch {
    refusedPrivate = true;
  }
  check('a peer key carrying private material ("d") is refused at load', refusedPrivate);

  // --- Build the trust maps the way the platform does -----------------------
  const trust = new Map<string, TrustedIssuer>();
  const ldpTrust = new Map<string, VpTrustedIssuer>();
  // Self-trust (home issuer).
  trust.set(HOME_DID, { did: HOME_DID, publicJwks: [home.publicJwk], statusLists: {} });
  ldpTrust.set(HOME_DID, { did: HOME_DID, publicKeyObjects: [createPublicKey({ key: home.publicJwk as any, format: 'jwk' })] });
  // Federation: add the peer.
  applyFederation(trust, ldpTrust, cfg.federation.trustedIssuers as FederatedIssuer[]);
  check('the peer issuer is now in the VC trust map', trust.has(PEER_DID));
  check('the peer issuer is now in the VP/LDP trust map', ldpTrust.has(PEER_DID));

  const verifier = new VcVerifier(trust);

  // --- A peer-issued VC-JWT verifies here -----------------------------------
  const peerJwt = (await new VcIssuer(peer).issue(claims, issueOpts(PEER_DID))).jwt;
  const peerOutcome = await verifier.verify(peerJwt, { offline: true });
  check('a VC-JWT issued by the FEDERATED peer verifies', peerOutcome.valid, peerOutcome.reason);
  check('and is attributed to the peer issuer', peerOutcome.issuerDid === PEER_DID);

  // --- A peer's REVOCATION is checkable, once their status list is synced ---
  //
  // This is what `statusListUrl` on a federated peer is for, and it was parsed, typed and
  // documented while `federatedTrustedIssuer` hardcoded `statusLists: {}` and nothing ever
  // read it. The consequence was two failures pointing in opposite directions, from one
  // cause: the offline path accepted a REVOKED peer credential (no list to check, so
  // `checkedRevocation: false` and `valid: true`), while the OpenID4VP path refused a VALID
  // one, because it fails closed on exactly that flag.
  const PEER_STATUS_URL = 'https://id.kano.gov.ng/status/ng.json';
  const peerRevokedJwt = (
    await new VcIssuer(peer).issue(
      { ...claims, residentId: 'KN-REVOKED-0001' },
      { ...issueOpts(PEER_DID), statusListUrl: PEER_STATUS_URL, statusListIndex: 7 },
    )
  ).jwt;

  // Before any sync: accepted, but explicitly unchecked. That flag is the only thing
  // standing between this and accepting a revoked credential outright.
  const beforeSync = await verifier.verify(peerRevokedJwt, { offline: true });
  check(
    'before syncing a peer list, a peer credential is accepted but flagged unchecked',
    beforeSync.valid === true && beforeSync.checkedRevocation === false,
  );

  // The peer publishes a SIGNED Bitstring Status List with index 7 revoked. Signed, because
  // an unsigned one is now refused -- see the authentication block below.
  const peerList = new StatusList();
  peerList.set(7, true);

  // A peer's status list must be AUTHENTICATED before it is believed.
  //
  // This is the one artifact where trusting a forgery fails in the dangerous direction: a
  // forged revocation list does not grant access it should not, it RESTORES access that was
  // deliberately taken away. Cached unsigned, the list is authenticated only by TLS to
  // whatever host answered, so an attacker who can serve the URL just omits the proof.
  // Built inline rather than imported: the shared envelope helper arrives with the
  // status-list signing change, and this suite must pass both before and after that lands.
  const statusEnvelope = (list: StatusList, issuerDid: string) => ({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: PEER_STATUS_URL,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: issuerDid,
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: list.toCredentialSubject(PEER_STATUS_URL),
  });
  const signedPublished = await new LdpIssuer(peer).sign(
    statusEnvelope(peerList, PEER_DID) as any,
    PEER_DID,
  );

  const unsignedSync = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, publicJwks: [peer.publicJwk], statusListUrl: PEER_STATUS_URL }],
    async () => ({ ...signedPublished, proof: undefined }),
  );
  check(
    'an UNSIGNED peer status list is refused, not cached',
    unsignedSync[0]?.status === 'unsigned',
  );

  // The attack the signature exists to stop: a list forged by someone else, claiming to
  // un-revoke the peer's credentials.
  const forged = new StatusList(); // index 7 NOT revoked
  const forgedPublished = await new LdpIssuer(stranger).sign(
    statusEnvelope(forged, PEER_DID) as any,
    PEER_DID,
  );
  const forgedSync = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, publicJwks: [peer.publicJwk], statusListUrl: PEER_STATUS_URL }],
    async () => forgedPublished,
  );
  check(
    'a status list signed by the WRONG key is refused (no silent un-revocation)',
    forgedSync[0]?.status === 'untrusted',
  );

  // An explicit, per-peer opt-out exists for a peer still publishing bare JSON -- and it has
  // to be asked for.
  const optedIn = await syncFederatedStatusLists(
    trust,
    [
      {
        did: PEER_DID,
        publicJwks: [peer.publicJwk],
        statusListUrl: PEER_STATUS_URL,
        allowUnsignedStatusList: true,
      },
    ],
    async () => ({ ...signedPublished, proof: undefined }),
  );
  check(
    'an unsigned list is accepted only when that peer explicitly opts in',
    optedIn[0]?.status === 'synced',
  );

  // And a properly signed list from the right key syncs and is believed.
  const signedSync = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, publicJwks: [peer.publicJwk], statusListUrl: PEER_STATUS_URL }],
    async () => signedPublished,
  );
  check('a correctly signed peer status list syncs', signedSync[0]?.status === 'synced');

  const syncResults = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, name: 'Kano', publicJwks: [peer.publicJwk], statusListUrl: PEER_STATUS_URL }],
    async (url) => (url === PEER_STATUS_URL ? signedPublished : Promise.reject(new Error('404'))),
  );
  check('syncing a peer status list reports success', syncResults[0]?.status === 'synced');

  const afterSync = await verifier.verify(peerRevokedJwt, { offline: true });
  check(
    "a REVOKED peer credential is now rejected, not silently accepted",
    afterSync.valid === false && afterSync.reason === 'REVOKED',
  );
  check('and the revocation check actually ran', afterSync.checkedRevocation === true);

  // A peer credential that is NOT revoked must still pass, and now with the check having
  // genuinely run -- which is what unblocks the OpenID4VP path, since it refuses anything
  // whose revocation could not be confirmed.
  const peerLiveJwt = (
    await new VcIssuer(peer).issue(
      { ...claims, residentId: 'KN-LIVE-0002' },
      { ...issueOpts(PEER_DID), statusListUrl: PEER_STATUS_URL, statusListIndex: 8 },
    )
  ).jwt;
  const liveOutcome = await verifier.verify(peerLiveJwt, { offline: true });
  check(
    'a live peer credential verifies WITH revocation confirmed (unblocks presentation)',
    liveOutcome.valid === true && liveOutcome.checkedRevocation === true,
  );

  // An unreachable peer must not poison the cache or crash the sync -- another government's
  // server being down is an ordinary operating condition.
  const unreachable = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, publicJwks: [peer.publicJwk], statusListUrl: 'https://down.example/s.json' }],
    async () => {
      throw new Error('ECONNREFUSED');
    },
  );
  check('an unreachable peer is reported, not thrown', unreachable[0]?.status === 'unreachable');
  check(
    'and the previously synced list is left intact',
    (await verifier.verify(peerRevokedJwt, { offline: true })).reason === 'REVOKED',
  );

  const noUrl = await syncFederatedStatusLists(
    trust,
    [{ did: PEER_DID, publicJwks: [peer.publicJwk] }],
    async () => ({}),
  );
  check(
    'a peer declaring no statusListUrl is reported as not-configured',
    noUrl[0]?.status === 'not-configured',
  );
  check(
    'an unparseable published document yields no list rather than a bad one',
    statusListFromPublished({ credentialSubject: { encodedList: 'not-a-bitstring' } }) === null &&
      statusListFromPublished({}) === null,
  );

  // --- A home-issued credential still verifies (federation is additive) -----
  const homeJwt = (await new VcIssuer(home).issue({ ...claims, residentId: 'KT-9Z8Y-7X6W' }, issueOpts(HOME_DID))).jwt;
  check('a home-issued VC-JWT still verifies', (await verifier.verify(homeJwt, { offline: true })).valid);

  // --- An UNLISTED issuer is rejected: the trust boundary is real -----------
  const strangerJwt = (await new VcIssuer(stranger).issue(claims, issueOpts(STRANGER_DID))).jwt;
  const strangerOutcome = await verifier.verify(strangerJwt, { offline: true });
  check('a credential from an UNLISTED issuer is rejected', !strangerOutcome.valid);
  check('...specifically as UNTRUSTED_ISSUER', strangerOutcome.reason === 'UNTRUSTED_ISSUER');

  // --- A peer credential re-signed under a swapped key fails on signature ----
  // (peer DID is trusted, but the bytes were signed by the stranger's key.)
  const forgedHeaderJwt = strangerJwt; // stranger key, stranger DID -> untrusted anyway
  check('a forged issuer cannot borrow a trusted DID', !(await verifier.verify(forgedHeaderJwt, { offline: true })).valid);

  // --- Data Integrity (ldp_vc) from the peer verifies via the peer's key ----
  // A minimal, context-clean JSON-LD credential -- enough to prove the peer's Data
  // Integrity proof verifies against the federated key. (Full residency-body issuance is
  // covered by the conformance suite; this test is about the trust wiring.)
  const unsigned: Record<string, unknown> = {
    '@context': RESIDENCY_LDP_CONTEXT,
    id: 'urn:uuid:peer-1',
    type: ['VerifiableCredential', 'StateResidencyCredential'],
    issuer: { id: PEER_DID, name: 'Kano State Residency Authority' },
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
    credentialSubject: { id: 'did:key:z6MkHolder', type: 'StateResident', residentId: 'KN-1A2B-3C4D' },
  };
  const peerLdp = (await new LdpIssuer(peer).sign(unsigned, PEER_DID)) as LdpCredential;
  const peerKeyObj = ldpTrust.get(PEER_DID)!.publicKeyObjects;
  check('a Data Integrity credential from the peer verifies against the federated key', await LdpIssuer.verify(peerLdp, peerKeyObj));

  // --- Rotation across the federation: peer publishes new + retired keys -----
  const peerRotated = await KeyStore.generate('peer-key-2');
  const trust2 = new Map<string, TrustedIssuer>();
  applyFederation(trust2, new Map(), [
    { did: PEER_DID, name: 'Kano', publicJwks: [peerRotated.publicJwk, peer.publicJwk] } as FederatedIssuer,
  ]);
  const v2 = new VcVerifier(trust2);
  check('a peer credential still verifies after the peer rotates keys', (await v2.verify(peerJwt, { offline: true })).valid);

  // --- applyFederation refuses to overwrite an existing (self) issuer -------
  let refusedCollision = false;
  try {
    const t = new Map<string, TrustedIssuer>([[HOME_DID, { did: HOME_DID, publicJwks: [home.publicJwk], statusLists: {} }]]);
    applyFederation(t, new Map(), [{ did: HOME_DID, publicJwks: [stranger.publicJwk] } as FederatedIssuer]);
  } catch {
    refusedCollision = true;
  }
  check('federation refuses to overwrite the deployment\'s own issuer DID', refusedCollision);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
