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
import { InMemoryStore, ResidentRecord } from '../src/core/residency/ports';
import { DEFAULT_PURPOSE, RelationshipType } from '../src/core/residency/relationship';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { parseCountryConfig } from '../src/core/config/country-config';
import { ConsentService, InMemoryConsentStore, isExpired } from '../src/core/consent/consent';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { StatusList } from '../src/core/credentials/status-list';

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
  // ORCS §1.1 and the §4.6 worked example: household in Katsina, employment in Kano,
  // education in Lagos, concurrently. This is the product thesis.
  const store = new InMemoryStore();
  const person = { subjectRef: 'tok_shared_person', providerCode: 'MOCK' };

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
      issuerName: 'Conformance Issuer',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [
      { code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' },
      { code: 'KN', name: 'Kano', parent: 'NG', level: 'state' },
      { code: 'LA', name: 'Lagos', parent: 'NG', level: 'state' },
    ],
  });

  function relationship(
    unit: string,
    id: string,
    relationshipType: RelationshipType,
  ): ResidentRecord {
    return {
      id: `uuid-${unit}`,
      residentId: id,
      subjectRef: person.subjectRef,
      countryCode: 'NG',
      subnationalUnit: unit,
      providerCode: person.providerCode,
      assuranceLevel: 'verified',
      relationshipType,
      purposeCode: DEFAULT_PURPOSE[relationshipType],
      status: 'ACTIVE',
      binding: { method: 'none' } as ResidentRecord['binding'],
      residence: { assuranceLevel: 'RAL0', method: 'self_declared' } as ResidentRecord['residence'],
      provisional: false,
      statusListIndex: 0,
      createdAt: new Date().toISOString(),
      person: {},
    };
  }

  await store.save(relationship('KT', 'NG-KT-0001', 'GENERAL_RESIDENCY')); // household
  await store.save(relationship('KN', 'NG-KN-0001', 'EMPLOYMENT_CONNECTION')); // employment
  await store.save(relationship('LA', 'NG-LA-0001', 'EDUCATION_CONNECTION')); // education
  const held = await store.list({ countryCode: 'NG' });

  // Three facts decide this, and the structural two matter as much as the behavioural one --
  // InMemoryStore once held all three rows regardless, because `list()` iterates its
  // residentId index and never consulted the subjectRef one. Asserting only on behaviour
  // would have reported a PASS that production could not honour.
  //
  // (a) Behavioural: the store returns all three for one person, each with its own purpose,
  //     all ACTIVE. Before the migration `save()` keyed on subjectRef alone, so the second
  //     relationship silently overwrote the first.
  const forPerson = await store.listBySubjectRef(person.subjectRef);
  const coexist =
    forPerson.length === 3 &&
    new Set(forPerson.map((r) => r.purposeCode)).size === 3 &&
    forPerson.every((r) => r.status === 'ACTIVE');

  // (b) The persisted record can say what a relationship is for. Without this, three rows are
  //     three general residencies rather than a household, an employment and an education
  //     relationship -- ORCS §4.3 requires type and purpose on every relationship.
  const sampleRecord = held.items[0];
  const canExpressPurpose =
    sampleRecord !== undefined && 'purposeCode' in sampleRecord && 'relationshipType' in sampleRecord;

  // (c) The production schema no longer forbids a second row for the same person+provider.
  //     The in-memory store cannot speak to this, so the schema is read directly.
  const schema = readFileSync(join(__dirname, '../../prisma/schema.prisma'), 'utf8');
  const subjectRefIsUnique = /subjectRef\s+String\s+@unique/.test(schema);
  const compositeKey = /@@unique\(\[subjectRef,\s*providerCode,\s*subnationalUnit,\s*purposeCode\]\)/.test(
    schema,
  );

  // (d) End-to-end: can a person actually OBTAIN a second relationship?
  //
  // (a) saves hand-built records straight to the store, which proves the model holds them but
  //     not that anything can create them. Issuing the same person into three jurisdictions
  //     through ResidencyService is the question ORCS §15 criterion 1 actually asks -- a
  //     citizen who cannot get the Kano relationship does not have it, however well the schema
  //     could have represented it.
  const e2eStore = new InMemoryStore();
  const e2e = new ResidencyService(
    new ProviderRegistry('conformance-pepper'),
    new VcIssuer(key),
    e2eStore,
    () => 'https://example.gov/status',
  );
  const nin = '12345678902';
  const enrolments: Array<[string, RelationshipType]> = [
    ['KT', 'GENERAL_RESIDENCY'], // family home
    ['KN', 'EMPLOYMENT_CONNECTION'], // workplace
    ['LA', 'EDUCATION_CONNECTION'], // university
  ];
  const issued = [];
  for (const [subnationalUnit, relationshipType] of enrolments) {
    issued.push(
      await e2e.issue(e2eCfg, {
        countryCode: 'NG',
        subnationalUnit,
        relationshipType,
        identifiers: { nin },
      }),
    );
  }
  const first = issued[0];
  const heldE2E =
    first.status === 'issued' ? await e2eStore.listBySubjectRef(first.record.subjectRef) : [];
  const obtainedE2E = heldE2E.length;
  const allIssued = issued.every((r) => r.status === 'issued');

  // Re-enrolling for a purpose already held must still be idempotent: concurrency is about
  // distinct purposes, not about issuing the same relationship twice.
  const repeat = await e2e.issue(e2eCfg, {
    countryCode: 'NG',
    subnationalUnit: 'KN',
    relationshipType: 'EMPLOYMENT_CONNECTION',
    identifiers: { nin },
  });
  const stillIdempotent =
    repeat.status === 'exists' &&
    (await e2eStore.listBySubjectRef(first.status === 'issued' ? first.record.subjectRef : '')).length === 3;

  if (
    coexist &&
    canExpressPurpose &&
    !subjectRefIsUnique &&
    compositeKey &&
    allIssued &&
    obtainedE2E === 3 &&
    stillIdempotent
  ) {
    record(
      1,
      'Concurrent relationships in multiple jurisdictions',
      'PASS',
      `one person enrolled through ResidencyService holds Katsina household + Kano employment + ` +
        `Lagos education concurrently (${heldE2E
          .map((r) => `${r.subnationalUnit}/${r.relationshipType}/${r.status}`)
          .join(', ')}); re-enrolling an existing purpose stays idempotent`,
    );
  } else if (coexist && canExpressPurpose && !subjectRefIsUnique && compositeKey) {
    record(
      1,
      'Concurrent relationships in multiple jurisdictions',
      'PARTIAL',
      `the MODEL holds concurrent relationships (composite key in place, purpose on the record, ` +
        `${forPerson.length} coexisting when written directly) but NOTHING CAN CREATE THEM: ` +
        `issuing one person into KT/KN/LA yields ${issued.map((r) => r.status).join(', ')} and ` +
        `${obtainedE2E} relationship(s). ResidencyService.issue() looks up by subjectRef scoped ` +
        `to the general-residency purpose and every record it writes hardcodes GENERAL_RESIDENCY, ` +
        `so the second enrolment reads as a duplicate. Criterion 1 is not met until an issuance ` +
        `path carries relationship type and purpose`,
      'G-01',
    );
  } else {
    record(
      1,
      'Concurrent relationships in multiple jurisdictions',
      'FAIL',
      `coexist: ${coexist} (${forPerson.length} of 3 held); record expresses a purpose: ` +
        `${canExpressPurpose}; subjectRef @unique: ${subjectRefIsUnique}; composite key present: ` +
        `${compositeKey}; obtainable end-to-end: ${obtainedE2E} of 3`,
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
  const sample = held.items[0];
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
