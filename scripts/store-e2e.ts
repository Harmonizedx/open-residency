// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * The persistence contract: every field a store claims to keep, kept.
 *
 * Run by `scripts/run-store-e2e.sh` against a throwaway PostgreSQL with the committed
 * migrations applied. See that script for why this exists at all.
 *
 * ## The technique that makes it worth running
 *
 * Every value written here is chosen to DIFFER FROM THE COLUMN DEFAULT. That is the point.
 *
 * Typing the write objects catches a column that does not exist -- TypeScript rejects the
 * unknown key. It cannot catch a column that is silently OMITTED, because a column with a
 * schema default is legitimately optional in Prisma's create input. An omitted defaulted column
 * takes its default, quietly overriding whatever the service decided, and everything typechecks.
 *
 * That failure has already happened here once: a write path that did not set a status column
 * landed rows as ACTIVE when the service had decided otherwise, recorded as the third of three
 * false greens under G-01. Writing non-default values and reading them back is the only way to
 * see it: if a column is dropped from the write path, the read returns the default and the
 * assertion fails.
 */
import {
  PrismaService,
  PrismaResidencyStore,
  PrismaRefusalStore,
  PrismaOidcStore,
  PrismaIdentityLinkStore,
  PrismaDeliveryStore,
} from '../src/prisma/prisma.service';
import { IdentityLinkRegistry } from '../src/core/identity/identity-link';
import { ResidentRecord } from '../src/core/residency/ports';
import { RefusalRecord } from '../src/core/residency/refusal';

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

const ADDRESS = { lines: ['12 Ahmadu Bello Way'], postalCode: '800001', adminUnit: 'KT' };

/**
 * Deliberately non-default in every field that has a default.
 *
 * `provisional` true (default false), `residenceAssurance` RAL3 (default RAL0),
 * `residenceMethod` document (default self_declared), `bindingMethod` face_match (default
 * none), relationship SUSPENDED (default ACTIVE), credential SUSPENDED (default ACTIVE).
 */
function fullRecord(): ResidentRecord {
  return {
    id: '55555555-5555-5555-5555-555555555555',
    residentId: 'KT-FULL-0001-C' as ResidentRecord['residentId'],
    subjectRef: 'tok_store_e2e',
    countryCode: 'NG',
    subnationalUnit: 'KT',
    providerCode: 'MOCK',
    assuranceLevel: 'high',
    binding: {
      method: 'face_match',
      ref: 'match-abc',
      verifiedAt: '2026-01-02T03:04:05.000Z',
      score: 0.97,
    },
    residence: {
      assuranceLevel: 'RAL3',
      method: 'document',
      unit: 'KT',
      address: ADDRESS,
      asOf: '2026-01-01T00:00:00.000Z',
    },
    provisional: true,
    relationship: {
      type: 'FORMER_RESIDENCY',
      purpose: 'Subnational residency for service delivery',
      status: 'SUSPENDED',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: '2026-06-01T00:00:00.000Z',
      policyVersion: 'sha256:deadbeefdeadbeef',
      evidenceRefs: ['binding:face_match:match-abc', 'residence:document:RAL3'],
      assuranceProfileId: 'orcs:profile:high',
      issuer: 'did:web:id.katsina.gov.ng',
      decidedBy: 'automated:sha256:deadbeefdeadbeef',
      submittedBy: 'operator:Desk-9',
      decidedAt: '2026-01-01T00:00:00.000Z',
    },
    credentialStatus: {
      status: 'SUSPENDED',
      reason: 'Reported lost',
      authority: 'operator:Registrar',
      at: '2026-02-02T00:00:00.000Z',
      appealPath: 'Appeals office, 30 days',
    },
    credentialId: 'urn:uuid:cred-1',
    statusListIndex: 7,
    createdAt: '2026-01-01T00:00:00.000Z',
    person: {
      fullName: 'Amina Bello',
      givenName: 'Amina',
      familyName: 'Bello',
      dateOfBirth: '1990-04-04',
      gender: 'female',
    },
  };
}

async function main() {
  const prisma = new PrismaService();
  await prisma.$connect();
  const residency = new PrismaResidencyStore(prisma);
  const refusals = new PrismaRefusalStore(prisma);
  const oidc = new PrismaOidcStore(prisma);

  await prisma.resident.deleteMany({});
  await prisma.residencyRefusal.deleteMany({});
  await prisma.oidcStoredItem.deleteMany({});

  console.log('\n== persistence contract, against real PostgreSQL ==\n');

  console.log('a resident record survives a round trip, field for field:');
  const rec = fullRecord();
  await residency.save(rec);
  const r = await residency.findByResidentId(rec.residentId);
  check('the record loads', !!r);

  check('provisional (default false) survives as true', r?.provisional === true);
  check('assuranceLevel survives', r?.assuranceLevel === 'high');
  check('statusListIndex survives', r?.statusListIndex === 7);

  check('binding method (default none) survives', r?.binding.method === 'face_match');
  check('  binding ref survives', r?.binding.ref === 'match-abc');
  check('  binding score survives', r?.binding.score === 0.97);

  check('residence assurance (default RAL0) survives as RAL3', r?.residence.assuranceLevel === 'RAL3');
  check('  residence method (default self_declared) survives', r?.residence.method === 'document');
  check('  residence unit survives', r?.residence.unit === 'KT');
  check('  residence address survives', r?.residence.address?.lines?.[0] === ADDRESS.lines[0]);
  check('  its postcode survives', r?.residence.address?.postalCode === '800001');

  const rel = r?.relationship;
  check('relationship status (default ACTIVE) survives as SUSPENDED', rel?.status === 'SUSPENDED');
  check('  type (default GENERAL_RESIDENCY) survives as FORMER_RESIDENCY', rel?.type === 'FORMER_RESIDENCY');
  check('  purpose survives', rel?.purpose === 'Subnational residency for service delivery');
  check('  validFrom survives', rel?.validFrom === '2026-01-01T00:00:00.000Z');
  check('  validTo survives', rel?.validTo === '2026-06-01T00:00:00.000Z');
  check('  policyVersion survives', rel?.policyVersion === 'sha256:deadbeefdeadbeef');
  check('  evidenceRefs survive as an array', rel?.evidenceRefs.length === 2);
  check('  assuranceProfileId survives', rel?.assuranceProfileId === 'orcs:profile:high');
  check('  issuer survives', rel?.issuer === 'did:web:id.katsina.gov.ng');
  check('  decidedBy survives', rel?.decidedBy === 'automated:sha256:deadbeefdeadbeef');
  check('  submittedBy survives, distinct from decidedBy', rel?.submittedBy === 'operator:Desk-9');

  const cs = r?.credentialStatus;
  check('credential status (default ACTIVE) survives as SUSPENDED', cs?.status === 'SUSPENDED');
  check('  its reason survives', cs?.reason === 'Reported lost');
  check('  its authority survives', cs?.authority === 'operator:Registrar');
  check('  its appeal path survives', cs?.appealPath === 'Appeals office, 30 days');

  console.log('\nsave() updates in place rather than duplicating:');
  await residency.save({ ...r!, assuranceLevel: 'verified' });
  check('the update lands', (await residency.findByResidentId(rec.residentId))?.assuranceLevel === 'verified');
  check('  and there is still one row', (await residency.list({ countryCode: 'NG' })).total === 1);

  console.log('\nerasure destroys identity, including the address:');
  const erased = await residency.erase(rec.residentId, 'tombstone-store-e2e', new Date());
  check('the name is gone', !erased?.person.fullName);
  check('  the date of birth is gone', !erased?.person.dateOfBirth);
  check('  the ADDRESS is gone', !erased?.residence.address);
  check('  the subjectRef is tombstoned', erased?.subjectRef === 'tombstone-store-e2e');
  check('  the status-list index is KEPT, so the credential stays revocable', erased?.statusListIndex === 7);

  console.log('\na refusal survives, and keeps both actors apart:');
  const refusal: RefusalRecord = {
    reference: 'REF-AAAA-BBBB-CCCC-DDDD-EEEE',
    countryCode: 'NG',
    subnationalUnit: 'KT',
    subjectRef: 'tok_refused',
    reason: 'PROOF_OF_RESIDENCE_REQUIRED',
    decidedBy: 'automated:sha256:cafebabe',
    submittedBy: 'operator:Desk-3',
    appealPath: 'Appeals office',
    humanReviewPath: 'Reconsideration at any enrolment centre',
    reviewStatus: 'none',
    refusedAt: '2026-03-03T00:00:00.000Z',
  };
  await refusals.save(refusal);
  const rf = await refusals.findByReference(refusal.reference);
  check('the refusal loads', !!rf);
  check('  the reason survives', rf?.reason === 'PROOF_OF_RESIDENCE_REQUIRED');
  check('  what decided survives', rf?.decidedBy === 'automated:sha256:cafebabe');
  check('  who submitted survives, separately', rf?.submittedBy === 'operator:Desk-3');
  check('  the appeal path survives', rf?.appealPath === 'Appeals office');
  check('  the human-review path survives', rf?.humanReviewPath === 'Reconsideration at any enrolment centre');
  check('  reviewStatus starts at none', rf?.reviewStatus === 'none');

  const reviewed = await refusals.recordReview(refusal.reference, {
    status: 'overturned',
    by: 'operator:Reviewer',
    at: '2026-03-04T00:00:00.000Z',
    note: 'Number mistyped at the desk',
  });
  check('a human review overturns it', reviewed?.reviewStatus === 'overturned');
  check('  the reviewer is named', reviewed?.reviewedBy === 'operator:Reviewer');
  check('  their note survives', reviewed?.reviewNote === 'Number mistyped at the desk');
  check('  and it is found by tokenized subject too', (await refusals.listBySubjectRef('tok_refused')).length === 1);

  console.log('\nOIDC provider state survives, including the consumed marker:');
  const now = new Date();
  await oidc.upsert({
    name: 'AuthorizationCode',
    id: 'code-1',
    payload: { foo: 'bar', grantId: 'g1' },
    grantId: 'g1',
    uid: 'u1',
    userCode: 'ABCD',
    expiresAt: new Date(now.getTime() + 600_000),
  });
  const item = await oidc.find('AuthorizationCode', 'code-1', now);
  check('the item loads', !!item);
  check('  its payload survives', (item?.payload as any)?.foo === 'bar');
  check('  grantId is indexed out of the payload', item?.grantId === 'g1');
  check('  found by uid', (await oidc.findByUid('AuthorizationCode', 'u1', now))?.id === 'code-1');
  check('  found by userCode', (await oidc.findByUserCode('AuthorizationCode', 'ABCD', now))?.id === 'code-1');
  await oidc.consume('AuthorizationCode', 'code-1', now);
  check('consume marks it', !!(await oidc.find('AuthorizationCode', 'code-1', now))?.consumedAt);
  await oidc.upsert({
    name: 'AuthorizationCode',
    id: 'code-1',
    payload: { foo: 'bar2' },
    expiresAt: new Date(now.getTime() + 600_000),
  });
  check('  and a re-upsert does NOT clear it (a spent code stays spent)',
    !!(await oidc.find('AuthorizationCode', 'code-1', now))?.consumedAt);
  const expired = new Date(now.getTime() + 700_000);
  check('an expired item is not returned', (await oidc.find('AuthorizationCode', 'code-1', expired)) === null);
  check('  and the sweep removes it', (await oidc.purgeExpired(expired)) >= 1);

  console.log('\nIdentity links (ORCS §11) round-trip every column, and the registry runs unchanged on Postgres:');
  const linkStore = new PrismaIdentityLinkStore(prisma);
  const links = new IdentityLinkRegistry(linkStore);
  const l1 = await links.link({ personRef: 'KT-STORE-0001-1', identifierType: 'NIN', identifierRef: 'nin:store-a', by: 'operator:desk', evidenceRefs: ['foundational:NIN'], foundational: true, at: '2026-04-01T00:00:00.000Z' });
  check('a link saves and loads', l1.ok && (await linkStore.findLink(l1.ok ? l1.link.id : ''))?.status === 'ACTIVE');
  check('  identifierType is lower-cased and foundational survives', l1.ok && l1.link.identifierType === 'nin' && (await linkStore.findLink(l1.link.id))?.foundational === true);
  check('  evidence survives as an array', l1.ok && (await linkStore.findLink(l1.link.id))?.evidenceRefs.join() === 'foundational:NIN');
  check('  the current link is found by identifier', (await linkStore.findCurrentByIdentifier('nin:store-a'))?.personRef === 'KT-STORE-0001-1');
  const linkId = l1.ok ? l1.link.id : '';
  const d = await links.dispute(linkId, { by: 'operator:audit', reason: 'contested', at: '2026-04-02T00:00:00.000Z' });
  const dl = await linkStore.findLink(linkId);
  check('a dispute round-trips', d.ok && dl?.status === 'DISPUTED' && dl.dispute?.raisedBy === 'operator:audit' && dl.dispute.reason === 'contested');
  check('  a disputed link is still the current one for the identifier', (await linkStore.findCurrentByIdentifier('nin:store-a'))?.id === linkId);
  await links.resolveDispute(linkId, { by: 'operator:supervisor', resolution: 'verified', at: '2026-04-03T00:00:00.000Z' });
  const rl = await linkStore.findLink(linkId);
  check('  resolution fields survive', rl?.status === 'ACTIVE' && rl.dispute?.resolvedBy === 'operator:supervisor' && rl.dispute.resolution === 'verified' && rl.dispute.resolvedAt === '2026-04-03T00:00:00.000Z');
  const relinked = await links.relink(linkId, { toPersonRef: 'KT-STORE-0002-2', by: 'operator:supervisor', reason: 'adjudicated', evidenceRefs: ['case:1'], at: '2026-04-04T00:00:00.000Z' });
  const closed = await linkStore.findLink(linkId);
  check('a relink closes the source with operation RELINK', relinked.ok && closed?.status === 'UNLINKED' && closed.unlinked?.operation === 'RELINK' && closed.unlinked.reason === 'adjudicated');
  check('  supersedes / supersededBy chain both ways', relinked.ok && closed?.supersededBy === relinked.to.id && (await linkStore.findLink(relinked.to.id))?.supersedes === linkId);
  check('  the closed link is no longer current, the new one is', (await linkStore.findCurrentByIdentifier('nin:store-a'))?.id === (relinked.ok ? relinked.to.id : ''));
  check('  listByPerson returns the closed link for the old person', (await linkStore.listByPerson('KT-STORE-0001-1')).some((l) => l.id === linkId));
  const m = await links.merge({ survivorRef: 'KT-STORE-0003-3', duplicateRef: 'KT-STORE-0002-2', by: 'operator:admin', reason: 'duplicate', at: '2026-04-05T00:00:00.000Z' });
  const ml = await linkStore.findMerge(m.ok ? m.merge.id : '');
  check('a merge saves with its moved pairs as JSON', m.ok && ml?.moved.length === 1 && ml.moved[0].from === (relinked.ok ? relinked.to.id : '') && ml.split === undefined);
  check('  mergeId is on the survivor link', m.ok && (await linkStore.findLink(m.merge.moved[0].to))?.mergeId === m.merge.id);
  const sp = await links.split(m.ok ? m.merge.id : '', { by: 'operator:admin', reason: 'not the same', at: '2026-04-06T00:00:00.000Z' });
  const sl = await linkStore.findMerge(m.ok ? m.merge.id : '');
  check('a split saves onto the merge', sp.ok && sl?.split?.by === 'operator:admin' && sl.split.restored.length === 1);
  check('  the identifier is back with the duplicate', (await linkStore.findCurrentByIdentifier('nin:store-a'))?.personRef === 'KT-STORE-0002-2');
  const ev = await linkStore.listEvents({ personRef: 'KT-STORE-0002-2' });
  check('events read back in order with a database-assigned seq', ev.length >= 3 && ev.every((e, i) => i === 0 || e.seq > ev[i - 1].seq) && ev.map((e) => e.operation).includes('SPLIT'));
  check('  from/to person refs survive on a move', ev.some((e) => e.operation === 'RELINK' && e.fromPersonRef === 'KT-STORE-0001-1' && e.toPersonRef === 'KT-STORE-0002-2'));
  const byLink = await links.history(linkId);
  check('  a link\'s history includes the move that closed it', byLink.length === 4 && byLink.map((e) => e.operation).join(',') === 'LINK,DISPUTE,DISPUTE_RESOLVED,RELINK');

  console.log('\nCredential deliveries append, read back in order, and count without identifiers:');
  const deliveries = new PrismaDeliveryStore(prisma);
  const rid = 'KT-STORE-DELIV-1';
  await deliveries.append({ id: 'd-store-1', residentId: rid, countryCode: 'NG', credentialId: 'urn:cred:1', channel: 'sms_link', status: 'pending', at: '2026-05-01T10:00:00.000Z', by: 'operator:desk', evidenceRef: 'msg:1' });
  await deliveries.append({ id: 'd-store-2', residentId: rid, countryCode: 'NG', channel: 'agent_handover', status: 'failed', at: '2026-05-02T10:00:00.000Z', by: 'operator:field', failureReason: 'not at home' });
  await deliveries.append({ id: 'd-store-3', residentId: rid, countryCode: 'NG', credentialId: 'urn:cred:1', channel: 'agent_handover', status: 'delivered', at: '2026-05-03T10:00:00.000Z', by: 'operator:field' });
  const evs = await deliveries.listByResident(rid);
  check('three events read back, oldest first', evs.length === 3 && evs.map((e) => e.status).join(',') === 'pending,failed,delivered');
  check('  every column survives', evs[0].credentialId === 'urn:cred:1' && evs[0].evidenceRef === 'msg:1' && evs[0].by === 'operator:desk' && evs[1].failureReason === 'not at home' && evs[0].at === '2026-05-01T10:00:00.000Z');
  check('  absent optionals read back absent, not null', evs[1].credentialId === undefined && evs[1].evidenceRef === undefined);
  const counts = await deliveries.counts('NG');
  check('counts group by channel then status', counts.agent_handover?.failed === 1 && counts.agent_handover?.delivered === 1 && counts.sms_link?.pending === 1);
  check('  and are empty for a country with none', Object.keys(await deliveries.counts('XX')).length === 0);

  await prisma.$disconnect();
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});