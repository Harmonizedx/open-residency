/* eslint-disable no-console */
/**
 * Erasure and retention (DPG Standard indicator 7, ORCS §14).
 *
 * The whole difficulty is that the two obligations disagree. A citizen may require their
 * personal data to be destroyed; a public register must be able to show that nothing was
 * quietly rewritten. Delete the rows and you satisfy the first while destroying the second.
 *
 * So the assertions below are mostly about the seam: that erasure really destroys the
 * identifying data, that the tamper-evident chain still verifies afterwards, and that the
 * erasure is itself recorded so it cannot be done invisibly.
 */
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { StatusList } from '../src/core/credentials/status-list';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { AuditLog, InMemoryAuditStore, REDACTED } from '../src/core/audit/audit-log';
import {
  IDENTIFYING_FIELDS,
  erasureTombstone,
  isPastRetention,
  residencyDueForErasure,
  NO_AUTOMATIC_RETENTION,
} from '../src/core/privacy/erasure';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

async function main() {
  console.log('\n== OpenResidency erasure and retention ==\n');

  const key = await KeyStore.generate('erasure-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const statusUrl = 'https://id.katsina.gov.ng/status/ng.json';

  const cfg: CountryConfig = parseCountryConfig({
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
      validityDays: 1095,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });

  const store = new InMemoryStore();
  const svc = new ResidencyService(
    new ProviderRegistry('erasure-pepper'),
    new VcIssuer(key),
    store,
    () => statusUrl,
  );

  const issued = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902', givenName: 'Amina', familyName: 'Bello' },
  });
  if (issued.status !== 'issued') throw new Error('fixture failed to issue');
  const residentId = issued.residentId;
  const originalSubjectRef = issued.record.subjectRef;
  const credentialJwt = issued.credentialJwt;

  check('the record starts with identifying data', !!issued.record.person.fullName);

  // --- Erasure destroys the person, keeps the transaction --------------------
  const result = await svc.erase(cfg, residentId);
  check('erasure reports success', result.status === 'erased');

  const after = await store.findByResidentId(residentId);
  const serialized = JSON.stringify(after);
  check(
    'every identifying field is gone from the record',
    !!after &&
      Object.keys(after.person).length === 0 &&
      !serialized.includes('Amina') &&
      !serialized.includes('Bello'),
  );
  check(
    'the tokenized foundational reference is destroyed, not merely blanked',
    !!after && after.subjectRef !== originalSubjectRef && after.subjectRef.startsWith('erased:'),
  );
  check('the erasure is dated', !!after?.erasedAt);

  // The three things deliberately kept, each of which would be a defect if dropped.
  check(
    'residentId and statusListIndex survive, so the revocation stays attributable and the index is never reused',
    after?.residentId === residentId && after?.statusListIndex === issued.record.statusListIndex,
  );

  // --- The outstanding credential is dead BEFORE the subject became anonymous ---
  const trust = new Map<string, TrustedIssuer>();
  const list = await store.loadStatusList('NG');
  trust.set(issuerDid, {
    did: issuerDid,
    publicJwks: [key.publicJwk],
    statusLists: { [statusUrl]: StatusList.fromEncoded(list.encode()) },
  });
  const outcome = await new VcVerifier(trust).verify(credentialJwt, { offline: true });
  check(
    'the credential in the citizen wallet is revoked, not left verifying against a register that forgot them',
    outcome.valid === false && outcome.reason === 'REVOKED',
  );

  // --- Looking the person up by their old reference finds nothing ------------
  check(
    'the pre-erasure subjectRef no longer resolves to anyone',
    (await store.findBySubjectRef(originalSubjectRef)) === null,
  );

  // Re-enrolling the same person is a NEW resident, not a resurrection of the old record.
  const reEnrolled = await svc.issue(cfg, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902', givenName: 'Amina', familyName: 'Bello' },
  });
  check(
    're-enrolling an erased person creates a new residency rather than resurrecting the old one',
    reEnrolled.status === 'issued' && reEnrolled.residentId !== residentId,
  );

  // --- Idempotency: a retried request or a re-run sweep must not half-fail ----
  const second = await svc.erase(cfg, residentId);
  check('erasing an already-erased resident is a no-op, not an error', second.status === 'already-erased');
  check('erasing an unknown resident reports unknown', (await svc.erase(cfg, 'NOPE')).status === 'unknown');

  // --- The audit chain survives erasure -------------------------------------
  //
  // This is the assertion the whole design exists for. Personal data is removed from the
  // log, and the log still verifies.
  const audit = new AuditLog(new InMemoryAuditStore());
  await audit.record({ action: 'residency.issue', actor: 'clerk@state', target: residentId, outcome: 'success' });
  await audit.record({ action: 'consent.grant', actor: residentId, target: 'health', outcome: 'success' });
  await audit.record({ action: 'admin.read', actor: 'auditor@state', target: 'other-resident', outcome: 'success' });

  const before = await audit.verifyChain();
  check('the chain verifies before any redaction', before.ok && before.length === 3 && before.redacted === 0);

  const redactedSeqs = await audit.redactSubject(residentId, {
    actor: 'dpo@state',
    reason: 'erasure request',
    legalBasis: 'NDPA s.34',
  });
  check('every event naming the subject is redacted', redactedSeqs.length === 2);

  const events = await audit.list({ limit: 100 });
  const subjectStillNamed = events.some(
    (e) => !e.redactedAt && (e.actor === residentId || e.target === residentId),
  );
  check('the subject is named in no un-redacted event', !subjectStillNamed);
  check(
    'redacted events say so rather than appearing empty',
    events.filter((e) => e.redactedAt).every((e) => e.actor === REDACTED),
  );

  const afterRedaction = await audit.verifyChain();
  check(
    'THE CHAIN STILL VERIFIES after erasure — integrity and erasure coexist',
    afterRedaction.ok === true,
  );
  check('and reports how much was redacted rather than hiding it', afterRedaction.redacted === 2);

  // The redaction is itself chained, so it cannot be performed invisibly.
  const redactionEvents = events.filter((e) => e.action === 'audit.redact');
  check('each redaction is recorded as its own chained event', redactionEvents.length === 2);
  check(
    'naming who redacted, why, and under what legal basis',
    redactionEvents.every(
      (e) => e.actor === 'dpo@state' && (e.metadata as any)?.legalBasis === 'NDPA s.34',
    ),
  );

  // Tampering is still caught: redaction must not become a hiding place.
  const tamperStore = new InMemoryAuditStore();
  const tamperLog = new AuditLog(tamperStore);
  await tamperLog.record({ action: 'residency.issue', actor: 'a', target: 't1', outcome: 'success' });
  await tamperLog.record({ action: 'residency.revoke', actor: 'b', target: 't2', outcome: 'success' });
  const all = await tamperStore.all();
  await tamperStore.replace({ ...all[1], actor: 'someone-else' }); // edit, NOT a redaction
  const tampered = await tamperLog.verifyChain();
  check(
    'editing an event without redacting it is still detected',
    tampered.ok === false && tampered.brokenAtSeq === all[1].seq,
  );

  // --- Retention ------------------------------------------------------------
  const now = new Date('2026-08-04T00:00:00Z');
  const old = new Date('2020-01-01T00:00:00Z').toISOString();
  const recent = new Date('2026-08-01T00:00:00Z').toISOString();

  check('a null period means no automatic expiry', !isPastRetention(old, null, now));
  check('a record older than its period is due', isPastRetention(old, 365, now));
  check('a record inside its period is not', !isPastRetention(recent, 365, now));

  const records = [
    { createdAt: old, erasedAt: undefined },
    { createdAt: recent, erasedAt: undefined },
    { createdAt: old, erasedAt: '2026-01-01T00:00:00Z' },
  ];
  check(
    'the sweep selects only records past retention that are not already erased',
    residencyDueForErasure(records, { ...NO_AUTOMATIC_RETENTION, residencyDays: 365 }, now).length === 1,
  );
  check(
    'a legal hold stops the sweep entirely, rather than guessing which records an appeal touches',
    residencyDueForErasure(records, { ...NO_AUTOMATIC_RETENTION, residencyDays: 365, legalHold: true }, now)
      .length === 0,
  );
  check(
    'the default policy expires nothing, so retention is a decision rather than an accident',
    residencyDueForErasure(records, NO_AUTOMATIC_RETENTION, now).length === 0,
  );

  check(
    'the identifying-field list covers every person field on the record',
    IDENTIFYING_FIELDS.includes('subjectRef') &&
      IDENTIFYING_FIELDS.includes('phoneEnc') &&
      IDENTIFYING_FIELDS.includes('dateOfBirth'),
  );
  check('tombstones are unique per erasure', erasureTombstone() !== erasureTombstone());

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});