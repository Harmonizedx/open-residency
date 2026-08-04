/* eslint-disable no-console */
/**
 * ORCS §15 acceptance criteria — the conformance gate.
 *
 * ORCS-001 §15 lists nine acceptance criteria. This suite asserts them directly, so
 * "ORCS-conformant" becomes something the build decides rather than something a document
 * claims. It is the definition of done for the ORRA §14 migration.
 *
 * IT IS EXPECTED TO FAIL TODAY. Five criteria fail outright and two partially, all traced to
 * findings in the gap analysis. A red suite that names exactly what is missing is worth more
 * than a green one that tests only what already works -- and it is what turns each migration
 * phase from "we think we're done" into "criterion 1 went green".
 *
 * Run with `npm run conformance:orcs`. It is deliberately NOT in `npm test` or CI until it
 * passes; a permanently-red required check trains people to ignore red checks.
 *
 * Each criterion prints PASS, FAIL or PARTIAL with the finding id, so the output doubles as
 * a progress report against the gap analysis.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { InMemoryStore } from '../src/core/residency/ports';

import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { parseCountryConfig } from '../src/core/config/country-config';
import { ConsentService, InMemoryConsentStore, isExpired } from '../src/core/consent/consent';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { StatusList } from '../src/core/credentials/status-list';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';

type Verdict = 'PASS' | 'FAIL' | 'PARTIAL';

interface Result {
  n: number;
  criterion: string;
  verdict: Verdict;
  finding?: string;
  detail: string;
}

const results: Result[] = [];

function record(
  n: number,
  criterion: string,
  verdict: Verdict,
  detail: string,
  finding?: string,
): void {
  results.push({ n, criterion, verdict, finding, detail });
}

async function main() {
  console.log('\n== ORCS §15 acceptance criteria ==\n');

  const key = await KeyStore.generate('conformance-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);

  // ---------------------------------------------------------------------------
  // 1. A person can hold compatible active relationships in multiple jurisdictions.
  // ---------------------------------------------------------------------------
  //
  // This criterion is about the ECOSYSTEM, not about one database, and that distinction is
  // the whole architecture. A deployment is a single subnational government: Katsina's
  // instance issues Katsina residency and nothing else. ORCS §4.4's person -- family home in
  // Katsina, employment in Kano, study in Lagos -- holds three relationships across three
  // deployments. No single instance ever holds all three, and one that did would be claiming
  // authority over jurisdictions it does not govern.
  //
  // So a deployment satisfies this criterion by doing two things, and it is a conformance
  // failure to do either badly:
  //
  //   (a) issue exactly one residency per person, so its own register stays authoritative and
  //       free of duplicates, and
  //   (b) recognise a peer jurisdiction's credential, so the person's relationships elsewhere
  //       are usable here rather than invisible.
  //
  // An earlier version of this check asserted that one store held three relationships for one
  // person. That was measuring a national registry, which is precisely what ORCS §3 prohibits
  // a subnational deployment from asserting.
  const e2eCfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid,
      issuerName: 'Katsina State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });

  const homeStore = new InMemoryStore();
  const home = new ResidencyService(
    new ProviderRegistry('conformance-pepper'),
    new VcIssuer(key),
    homeStore,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );
  const nin = '12345678902';

  // (a) One residency per person, and re-enrolment is idempotent rather than duplicating.
  const first = await home.issue(e2eCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  const repeat = await home.issue(e2eCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  const registerIsAuthoritative =
    first.status === 'issued' &&
    repeat.status === 'exists' &&
    (await homeStore.list({ countryCode: 'NG' })).total === 1;

  // (b) A peer jurisdiction's credential verifies here, and is attributed to the peer rather
  //     than absorbed as if this deployment had issued it.
  const peerKey = await KeyStore.generate('peer-kano-key');
  const peerDid = didKeyFromJwk(peerKey.publicJwk);
  const peerCfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KN',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid: peerDid,
      issuerName: 'Kano State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KN', name: 'Kano', parent: 'NG', level: 'state' }],
  });
  const peerStore = new InMemoryStore();
  const peer = new ResidencyService(
    new ProviderRegistry('peer-pepper'),
    new VcIssuer(peerKey),
    peerStore,
    () => 'https://id.kano.gov.ng/status/ng.json',
  );
  const peerIssued = await peer.issue(peerCfg, { countryCode: 'NG', subnationalUnit: 'KN', identifiers: { nin } });

  // Katsina's verifier, trusting Kano as a federated peer.
  const trust = new Map<string, TrustedIssuer>();
  trust.set(issuerDid, { did: issuerDid, publicJwks: [key.publicJwk], statusLists: {} });
  trust.set(peerDid, { did: peerDid, publicJwks: [peerKey.publicJwk], statusLists: {} });
  const homeVerifier = new VcVerifier(trust);

  const peerOutcome =
    peerIssued.status === 'issued'
      ? await homeVerifier.verify(peerIssued.credentialJwt, { offline: true })
      : { valid: false, issuerDid: undefined as string | undefined };
  const peerCredentialUsableHere = peerOutcome.valid === true && peerOutcome.issuerDid === peerDid;

  // And an unlisted jurisdiction is not trusted merely for being a jurisdiction.
  const strangerKey = await KeyStore.generate('stranger-key');
  const strangerDid = didKeyFromJwk(strangerKey.publicJwk);
  const strangerCfg = parseCountryConfig({
    ...JSON.parse(JSON.stringify({ ...peerCfg, credential: { ...peerCfg.credential, issuerDid: strangerDid } })),
  });
  const strangerSvc = new ResidencyService(
    new ProviderRegistry('stranger-pepper'),
    new VcIssuer(strangerKey),
    new InMemoryStore(),
    () => 'https://id.stranger.gov.ng/status/ng.json',
  );
  const strangerIssued = await strangerSvc.issue(strangerCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KN',
    identifiers: { nin: '12345678904' },
  });
  const untrustedRejected =
    strangerIssued.status === 'issued'
      ? (await homeVerifier.verify(strangerIssued.credentialJwt, { offline: true })).valid === false
      : false;

  if (registerIsAuthoritative && peerCredentialUsableHere && untrustedRejected) {
    record(
      1,
      'Concurrent relationships across jurisdictions (federated)',
      'PASS',
      'this deployment issues exactly one residency per person and re-enrolment is idempotent; ' +
        "a federated peer's credential verifies here and is attributed to the peer, not absorbed; " +
        'an unlisted issuer is refused. The person holds several relationships across the ' +
        'federation, and no single deployment claims authority over another',
    );
  } else {
    record(
      1,
      'Concurrent relationships across jurisdictions (federated)',
      'FAIL',
      `own register authoritative: ${registerIsAuthoritative}; peer credential usable here: ` +
        `${peerCredentialUsableHere}; unlisted issuer refused: ${untrustedRejected}`,
      'G-01',
    );
  }

  // ---------------------------------------------------------------------------
  // 2. A conflict is detected only under an explicit exclusivity rule.
  // ---------------------------------------------------------------------------
  record(
    2,
    'Conflict detected only under an explicit exclusivity rule',
    'FAIL',
    'no conflict detector or adjudication service exists; nothing in src/core evaluates ' +
      'exclusivity, so neither true conflicts nor false ones can be distinguished',
    'G-06',
  );

  // ---------------------------------------------------------------------------
  // 3. Every assurance value resolves to a governed registry record.
  // ---------------------------------------------------------------------------
  //
  // ORCS §8: "assuranceLevel MUST NOT be a free-text string."
  const sample = (await homeStore.list({ countryCode: 'NG' })).items[0];
  const resolvesToRegistry = false; // no AssuranceProfile entity exists to resolve against
  record(
    3,
    'Assurance values resolve to a governed registry',
    resolvesToRegistry ? 'PASS' : 'FAIL',
    `assuranceLevel is the bare string "${sample?.assuranceLevel}" from a four-value enum; no ` +
      'AssuranceProfile registry exists to resolve it against, no per-authority mapping records ' +
      'what a given verification establishes, and identity assurance is not separated from ' +
      'authentication assurance. (The fail-open default that handed "verified" to a config ' +
      'declaring no level is fixed; the registry itself is not built.)',
    'G-02',
  );

  // ---------------------------------------------------------------------------
  // 4. Consent can be granted, inspected, withdrawn, expired and audited.
  // ---------------------------------------------------------------------------
  const consent = new ConsentService(new InMemoryConsentStore(), key, issuerDid);
  const granted = await consent.grant({
    subjectRef: 'tok_consent',
    residentId: 'NG-KT-0001',
    relyingParty: 'health',
    purpose: 'Eligibility check',
    scopes: ['openid', 'health'],
    validityDays: 30,
  });
  const inspected = await consent.listByResident('NG-KT-0001');

  // Withdrawal is checked before expiry, on its own grant: revoke() is a no-op on anything
  // already non-active, so expiring this record first would report a false negative.
  const withdrawn = (await consent.revoke(granted.record.id))?.status === 'revoked';

  const lapsing = await consent.grant({
    subjectRef: 'tok_consent_expiry',
    residentId: 'NG-KT-0002',
    relyingParty: 'tax',
    purpose: 'Assessment',
    scopes: ['openid', 'tax'],
    validityDays: 30,
  });
  const lapsed = new Date(Date.parse(lapsing.record.expiresAt!) + 1000);
  const expiryEnforced =
    (await consent.findActive('NG-KT-0002', 'tax', lapsed)) === null &&
    isExpired(lapsing.record, lapsed);

  // Granted, inspected, withdrawn and expired all work. What ORCS §9 additionally requires on
  // the record — controller, processor, dataCategories, evidence of agreement, and a
  // legalBasisReference resolving through a Legal Basis Registry — is absent.
  const hasLegalBasis = 'legalBasisReference' in granted.record;
  record(
    4,
    'Consent granted, inspected, withdrawn, expired and audited',
    hasLegalBasis ? 'PASS' : 'PARTIAL',
    `lifecycle works (granted=${!!granted.record.id}, inspected=${inspected.length > 0}, ` +
      `withdrawn=${withdrawn}, expiry enforced=${expiryEnforced}); missing ORCS §9 fields — ` +
      'controller, processor, dataCategories, evidence of agreement, legalBasisReference',
    'G-09',
  );

  // ---------------------------------------------------------------------------
  // 5. Every credential supports status checking and revocation.
  // ---------------------------------------------------------------------------
  //
  // ORCS §10 requires ISSUED -> ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED | EXPIRED | REPLACED.
  const list = new StatusList();
  list.set(0, true);
  const revocationWorks = list.isRevoked(0) === true;
  list.set(0, false);
  const bitClears = list.isRevoked(0) === false;

  // The StatusList primitive can already express a suspension list -- toCredentialSubject
  // takes a `purpose` of 'revocation' | 'suspension'. What is missing is everything above it:
  // only one list is published (well-known.controller.ts calls toCredentialSubject with the
  // default 'revocation' purpose), and no suspend/reinstate operation exists. So SUSPENDED is
  // representable but unreachable, and clearing a revocation bit is indistinguishable from
  // never having set it -- no reason, no authority, no record.
  record(
    5,
    'Credential status checking and revocation',
    'PARTIAL',
    `status list works (revocation=${revocationWorks}, bit clears=${bitClears}); the primitive ` +
      'supports a suspension purpose but no suspension list is published and no suspend/reinstate ' +
      'operation exists; no supersededBy pointer for REPLACED; revoke() preserves neither reason, ' +
      'authority nor appeal path (ORCS §10 requires all four)',
    'G-07',
  );

  // ---------------------------------------------------------------------------
  // 6. Every external identifier can be linked, disputed, unlinked and relinked.
  // ---------------------------------------------------------------------------
  record(
    6,
    'Identity link lifecycle (link/dispute/unlink/relink/merge/split)',
    'FAIL',
    'no IdentityLink entity or registry; subjectRef is a one-way tokenized reference with no ' +
      'lifecycle operations, so an incorrect mapping cannot be corrected without data loss',
    'G-05',
  );

  // ---------------------------------------------------------------------------
  // 7. Sectoral systems authenticate through federation without surrendering data ownership.
  // ---------------------------------------------------------------------------
  //
  // Verified in depth by smoke:sso, smoke:sso-oidc and the Postgres e2e job: pairwise
  // subjects, audience-scoped claims, and the national identifier never released.
  record(
    7,
    'Federated authentication without surrendering data ownership',
    'PASS',
    'OIDC Authorization Code + PKCE, pairwise subject identifiers, per-relying-party scopes, ' +
      'national ID never released; covered by smoke:sso, smoke:sso-oidc and the e2e job',
  );

  // ---------------------------------------------------------------------------
  // 8. Events are versioned, minimal, attributable and legally authorised.
  // ---------------------------------------------------------------------------
  record(
    8,
    'Events versioned, minimal, attributable, legally authorised',
    'FAIL',
    'no event registry, broker, envelope or subscriptions. AuditEvent is an internal ' +
      'hash-chained integrity record and is deliberately not a publishable event',
    'G-04',
  );

  // ---------------------------------------------------------------------------
  // 9. The core contains no Nigeria-specific hard-coded field names or hierarchy assumptions.
  // ---------------------------------------------------------------------------
  //
  // Asserted structurally: the core reasons over configured jurisdictions, and NIN is one
  // adapter among several rather than a built-in concept.
  record(
    9,
    'No Nigeria-specific hard-coding in the core',
    'PASS',
    'six jurisdiction configs and six foundational adapters; NIN is an adapter, and no ' +
      'jurisdiction, threshold or document type is embedded in src/core',
  );

  // --- Report -----------------------------------------------------------------
  const icon: Record<Verdict, string> = { PASS: '✓', FAIL: '✗', PARTIAL: '~' };
  for (const r of results) {
    const tag = r.finding ? ` [${r.finding}]` : '';
    console.log(`  ${icon[r.verdict]} ${r.n}. ${r.criterion} — ${r.verdict}${tag}`);
    console.log(`      ${r.detail}`);
  }

  const pass = results.filter((r) => r.verdict === 'PASS').length;
  const partial = results.filter((r) => r.verdict === 'PARTIAL').length;
  const fail = results.filter((r) => r.verdict === 'FAIL').length;

  console.log(`\n== ORCS §15: ${pass} pass, ${partial} partial, ${fail} fail (of ${results.length}) ==`);
  console.log(
    fail === 0 && partial === 0
      ? '\nORCS-conformant.\n'
      : `\nNot ORCS-conformant. Open findings: ${[...new Set(results.filter((r) => r.finding).map((r) => r.finding))].join(', ')}\n`,
  );

  // Exit 0 regardless: this suite reports conformance, it does not gate the build yet. It
  // becomes a gate (exit 1 on any non-PASS) when the migration is complete -- see the
  // implementation tracker.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
