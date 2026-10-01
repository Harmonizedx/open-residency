// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Identity links: every external identifier can be linked, disputed, unlinked and relinked,
 * duplicates can be merged and a merge reversed, and none of it deletes anything (ORCS §11).
 *
 * Two halves. The first drives the registry on its own, operation by operation, including
 * the refusals: a link with no evidence, an identifier already held by somebody else, a
 * merge over an open dispute, a split over a later decision. The second drives it through
 * the residency service, which is where the registry earns its keep: a person enrolled under
 * the wrong record can be moved to the right one and found there afterwards, and a disputed
 * link stops a credential being issued until somebody has looked.
 */
import {
  IdentityLinkRegistry,
  InMemoryIdentityLinkStore,
} from '../src/core/identity/identity-link';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig } from '../src/core/config/country-config';
import { relationshipOf } from '../src/core/residency/lifecycle';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function registryAlone() {
  console.log('\n-- the registry, operation by operation --');
  let tick = 0;
  const reg = new IdentityLinkRegistry(
    new InMemoryIdentityLinkStore(),
    () => new Date(Date.UTC(2026, 8, 30, 12, 0, tick++)).toISOString(),
  );
  const ALICE = 'KT-AAAA-0001-1';
  const BOB = 'KT-BBBB-0002-2';
  const NIN_A = 'nin:aaaa';
  const HEALTH = 'nhis:h1';

  // LINK
  const l1 = await reg.link({ personRef: ALICE, identifierType: 'NIN', identifierRef: NIN_A, by: 'operator:desk1', evidenceRefs: ['foundational:NIN'], foundational: true });
  check('a foundational identifier links to a person', l1.ok && l1.created && l1.link.status === 'ACTIVE' && !!l1.link.foundational);
  const again = await reg.link({ personRef: ALICE, identifierType: 'NIN', identifierRef: NIN_A, by: 'operator:desk1', evidenceRefs: ['foundational:NIN'] });
  check('linking the same identifier to the same person again is idempotent', again.ok && !again.created && again.link.id === (l1.ok ? l1.link.id : ''));
  const stolen = await reg.link({ personRef: BOB, identifierType: 'NIN', identifierRef: NIN_A, by: 'operator:desk2', evidenceRefs: ['x'] });
  check('an identifier held by another person cannot simply be linked again', !stolen.ok && stolen.reason === 'IDENTIFIER_LINKED_TO_ANOTHER_PERSON');
  const noEvidence = await reg.link({ personRef: ALICE, identifierType: 'nhis', identifierRef: HEALTH, by: 'operator:desk1', evidenceRefs: [] });
  check('a link with no evidence is refused', !noEvidence.ok && noEvidence.reason === 'EVIDENCE_REQUIRED');
  const noActor = await reg.link({ personRef: ALICE, identifierType: 'nhis', identifierRef: HEALTH, by: ' ', evidenceRefs: ['card'] });
  check('a link with nobody deciding is refused', !noActor.ok && noActor.reason === 'DECIDING_ACTOR_REQUIRED');
  const l2 = await reg.link({ personRef: ALICE, identifierType: 'NHIS', identifierRef: HEALTH, by: 'operator:clinic', evidenceRefs: ['nhis-card:scan-77'] });
  check('a sector identifier links with evidence, type normalised', l2.ok && l2.link.identifierType === 'nhis');
  check('the person resolves from either identifier', (await reg.resolvePerson(NIN_A)) === ALICE && (await reg.resolvePerson(HEALTH)) === ALICE);

  // DISPUTE
  const healthId = l2.ok ? l2.link.id : '';
  const noReason = await reg.dispute(healthId, { by: 'operator:audit', reason: '' });
  check('a dispute without a reason is refused', !noReason.ok && noReason.reason === 'REASON_REQUIRED');
  const d = await reg.dispute(healthId, { by: 'operator:audit', reason: 'Card belongs to a sibling' });
  check('a link can be disputed', d.ok && d.link.status === 'DISPUTED' && d.link.dispute?.reason === 'Card belongs to a sibling');
  check('a disputed link restricts high-risk use for the person', (await reg.restrictions(ALICE)).restricted);
  check('a disputed identifier still resolves to the person while under review', (await reg.resolvePerson(HEALTH)) === ALICE);
  const twice = await reg.dispute(healthId, { by: 'operator:audit', reason: 'again' });
  check('disputing twice is refused', !twice.ok && twice.reason === 'ALREADY_DISPUTED');
  const upheld = await reg.resolveDispute(healthId, { by: 'operator:supervisor', resolution: 'Card verified against scheme register' });
  check('a dispute can be resolved in the link\'s favour', upheld.ok && upheld.link.status === 'ACTIVE' && upheld.link.dispute?.resolvedBy === 'operator:supervisor');
  check('resolving lifts the restriction', !(await reg.restrictions(ALICE)).restricted);
  const notDisputed = await reg.resolveDispute(healthId, { by: 'operator:supervisor', resolution: 'x' });
  check('resolving a link that is not disputed is refused', !notDisputed.ok && notDisputed.reason === 'LINK_NOT_DISPUTED');

  // UNLINK
  await reg.dispute(healthId, { by: 'operator:audit', reason: 'Second look' });
  const u = await reg.unlink(healthId, { by: 'operator:supervisor', reason: 'Scheme confirms the number is not hers' });
  check('a link can be unlinked with a reason', u.ok && u.link.status === 'UNLINKED' && u.link.unlinked?.operation === 'UNLINK');
  check('unlinking closes the open dispute rather than leaving it dangling', u.ok && !!u.link.dispute?.resolvedAt && !!u.link.dispute.resolution?.startsWith('UNLINK'));
  check('the unlinked identifier no longer resolves', (await reg.resolvePerson(HEALTH)) === null);
  check('the unlinked link is still there with its history', (await reg.find(healthId))?.status === 'UNLINKED' && (await reg.history(healthId)).map((e) => e.operation).join(',') === 'LINK,DISPUTE,DISPUTE_RESOLVED,DISPUTE,UNLINK');
  const uu = await reg.unlink(healthId, { by: 'operator:supervisor', reason: 'again' });
  check('unlinking twice is refused', !uu.ok && uu.reason === 'ALREADY_UNLINKED');

  // RELINK, from an unlinked source and from an active one
  const r1 = await reg.relink(healthId, { toPersonRef: BOB, by: 'operator:supervisor', reason: 'Adjudicated: the card is Bob\'s', evidenceRefs: ['adjudication:case-9'] });
  check('an unlinked identifier can be relinked to the right person', r1.ok && r1.to.personRef === BOB && r1.to.status === 'ACTIVE' && r1.to.supersedes === healthId);
  check('the old link points at its successor', r1.ok && r1.from.supersededBy === r1.to.id);
  check('the identifier now resolves to the right person', (await reg.resolvePerson(HEALTH)) === BOB);
  const stale = await reg.relink(healthId, { toPersonRef: ALICE, by: 'operator:x', reason: 'r', evidenceRefs: ['e'] });
  check('relinking from a link the identifier has since left is refused', !stale.ok && stale.reason === 'IDENTIFIER_LINKED_TO_ANOTHER_PERSON');
  const bobHealth = r1.ok ? r1.to.id : '';
  const r2 = await reg.relink(bobHealth, { toPersonRef: ALICE, by: 'operator:supervisor', reason: 'Reversed on appeal', evidenceRefs: ['appeal:12'] });
  check('an active link can be relinked, closing the source as RELINK', r2.ok && r2.from.status === 'UNLINKED' && r2.from.unlinked?.operation === 'RELINK' && r2.to.personRef === ALICE);
  const same = await reg.relink(r2.ok ? r2.to.id : '', { toPersonRef: ALICE, by: 'operator:x', reason: 'r', evidenceRefs: ['e'] });
  check('relinking to the person it is already linked to is refused', !same.ok && same.reason === 'ALREADY_LINKED_TO_THAT_PERSON');

  // MERGE and SPLIT
  const NIN_B = 'nin:bbbb';
  await reg.link({ personRef: BOB, identifierType: 'NIN', identifierRef: NIN_B, by: 'operator:desk2', evidenceRefs: ['foundational:NIN'], foundational: true });
  const self = await reg.merge({ survivorRef: ALICE, duplicateRef: ALICE, by: 'operator:admin', reason: 'r' });
  check('merging a person with themself is refused', !self.ok && self.reason === 'CANNOT_MERGE_PERSON_WITH_SELF');
  const bobNin = (await reg.linksFor(BOB)).find((l) => l.identifierRef === NIN_B)!;
  await reg.dispute(bobNin.id, { by: 'operator:audit', reason: 'typo suspected' });
  const overDispute = await reg.merge({ survivorRef: ALICE, duplicateRef: BOB, by: 'operator:admin', reason: 'Same person enrolled twice' });
  check('a merge over an open dispute is refused', !overDispute.ok && overDispute.reason === 'DISPUTED_LINKS_MUST_BE_RESOLVED');
  await reg.resolveDispute(bobNin.id, { by: 'operator:supervisor', resolution: 'Confirmed duplicate' });
  const m = await reg.merge({ survivorRef: ALICE, duplicateRef: BOB, by: 'operator:admin', reason: 'Same person enrolled twice under a typo' });
  check('a duplicate person merges into the survivor', m.ok && m.merge.moved.length === 1);
  check('the moved identifier resolves to the survivor', (await reg.resolvePerson(NIN_B)) === ALICE);
  check('the duplicate keeps its closed link, marked MERGE', (await reg.find(bobNin.id))?.unlinked?.operation === 'MERGE');
  const empty = await reg.merge({ survivorRef: ALICE, duplicateRef: BOB, by: 'operator:admin', reason: 'again' });
  check('a person with nothing left to merge is refused', !empty.ok && empty.reason === 'NOTHING_TO_MERGE');
  const mergeId = m.ok ? m.merge.id : '';
  const s = await reg.split(mergeId, { by: 'operator:admin', reason: 'Not the same person after all' });
  check('a merge can be split, restoring the identifier to the duplicate', s.ok && !!s.merge.split && (await reg.resolvePerson(NIN_B)) === BOB);
  const ss = await reg.split(mergeId, { by: 'operator:admin', reason: 'again' });
  check('splitting twice is refused', !ss.ok && ss.reason === 'ALREADY_SPLIT');
  const m2 = await reg.merge({ survivorRef: ALICE, duplicateRef: BOB, by: 'operator:admin', reason: 'Merged again after fresh review' });
  const movedTo = m2.ok ? m2.merge.moved[0].to : '';
  await reg.relink(movedTo, { toPersonRef: 'KT-CCCC-0003-3', by: 'operator:supervisor', reason: 'Belongs to a third person', evidenceRefs: ['e'] });
  const overLater = await reg.split(m2.ok ? m2.merge.id : '', { by: 'operator:admin', reason: 'undo' });
  check('a split over a later decision about the same identifier is refused', !overLater.ok && overLater.reason === 'LINK_MOVED_SINCE_MERGE');

  // Nothing deleted
  const bobHistory = await reg.historyFor(BOB);
  check('every operation is in the person\'s history, in order', bobHistory.length >= 6 && bobHistory.every((e, i) => i === 0 || e.seq > bobHistory[i - 1].seq));
  const allIds = [l1.ok ? l1.link.id : '', healthId, bobHealth, bobNin.id, movedTo];
  const stillThere = await Promise.all(allIds.map((id) => reg.find(id)));
  check('no link was ever deleted', stillThere.every((l) => l !== null));
}

async function throughTheService() {
  console.log('\n-- through the residency service --');
  const key = await KeyStore.generate('identity-link-smoke');
  const cfg = parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      identifierType: 'NIN',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid: didKeyFromJwk(key.publicJwk),
      issuerName: 'Katsina State Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });
  const store = new InMemoryStore();
  const links = new IdentityLinkRegistry(new InMemoryIdentityLinkStore());
  const svc = new ResidencyService(
    new ProviderRegistry('smoke-pepper'),
    new VcIssuer(key),
    store,
    () => 'https://id.katsina.gov.ng/status/ng.json',
    undefined,
    undefined,
    undefined,
    links,
  );
  const issue = (nin: string) => svc.issue(cfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin }, decidedBy: 'operator:desk1' });
  /** Narrow an issuance outcome to the two shapes that carry a record; anything else fails the check. */
  const withRecord = (r: Awaited<ReturnType<typeof issue>>) =>
    r.status === 'issued' || r.status === 'exists' ? { residentId: r.residentId, record: r.record } : { residentId: '', record: undefined };

  const aOut = await issue('12345678902');
  const a = withRecord(aOut);
  check('issuance links the foundational identifier to the new record', aOut.status === 'issued' && (await links.linksFor(a.residentId)).some((l) => l.foundational && l.status === 'ACTIVE'));
  const aLink = (await links.linksFor(a.residentId))[0];
  check('the link carries the tokenized reference, never the number', !!aLink && aLink.identifierRef === a.record?.subjectRef && !aLink.identifierRef.includes('12345678902'));

  // A disputed link blocks re-issuance until somebody has looked.
  await links.dispute(aLink.id, { by: 'operator:audit', reason: 'Applicant may have used a relative\'s NIN' });
  const blocked = await issue('12345678902');
  check('re-issuance is refused while the foundational link is disputed', blocked.status === 'rejected' && blocked.reason === 'IDENTITY_LINK_DISPUTED');
  await links.resolveDispute(aLink.id, { by: 'operator:supervisor', resolution: 'Applicant produced the slip' });
  const unblocked = await issue('12345678902');
  check('once resolved, issuance is idempotent again', unblocked.status === 'exists');

  // A duplicate enrolled under a typo is merged; the identifier then finds the survivor.
  const typoOut = await issue('12345678904');
  const typo = withRecord(typoOut);
  check('a second number enrols a second record (the typo case)', typoOut.status === 'issued');
  const merged = await svc.mergeResidents(cfg, {
    survivorId: a.residentId,
    duplicateId: typo.residentId,
    by: 'operator:admin',
    reason: 'Same person; second NIN was a typo confirmed at the desk',
  });
  check('merging moves the duplicate\'s identifier to the survivor', merged.ok && (await links.resolvePerson(typo.record!.subjectRef)) === a.residentId);
  const dupAfter = await store.findByResidentId(typo.record!.residentId);
  check('the duplicate\'s relationship is ENDED with a reason naming the survivor', !!dupAfter && relationshipOf(dupAfter).status === 'ENDED' && (relationshipOf(dupAfter).endedReason ?? '').includes(a.residentId));
  check('the duplicate\'s credential is REPLACED by the survivor\'s', dupAfter?.credentialStatus?.status === 'REPLACED' && dupAfter.credentialStatus.supersededBy === a.record!.credentialId);
  const viaTypo = await issue('12345678904');
  check('enrolling with the merged number now finds the survivor, not a stale duplicate', viaTypo.status === 'exists' && withRecord(viaTypo).residentId === a.residentId);
  const merge2 = await svc.mergeResidents(cfg, { survivorId: a.residentId, duplicateId: typo.residentId, by: 'operator:admin', reason: 'again' });
  check('merging the same pair again is refused', !merge2.ok && merge2.reason === 'NOTHING_TO_MERGE');

  // Split restores the identifier; the ended relationship stays ended and is re-evaluated by re-enrolment.
  const split = await svc.splitMerge(merged.ok ? merged.merge.id : '', { by: 'operator:admin', reason: 'They were two people' });
  check('a split restores the identifier to the duplicate', split.ok && (await links.resolvePerson(typo.record!.subjectRef)) === typo.residentId);
  const reissued = await issue('12345678904');
  check('the restored person re-enrols into a fresh relationship rather than resurrecting the ended one', reissued.status === 'issued' && withRecord(reissued).residentId === typo.residentId);

  // Unlinking the foundational identifier suspends the relationship first (ORCS §7).
  const bLink = (await links.linksFor(typo.residentId)).find((l) => l.status === 'ACTIVE' && l.foundational)!;
  const unlinked = await svc.unlinkIdentity(typo.residentId, bLink.id, { by: 'operator:supervisor', reason: 'Foundational record disowned by the register' });
  const afterUnlink = await store.findByResidentId(typo.record!.residentId);
  check('unlinking the foundational identifier suspends the relationship, then unlinks', unlinked.ok && relationshipOf(afterUnlink!).status === 'SUSPENDED' && unlinked.link.status === 'UNLINKED');
  const orphan = await issue('12345678904');
  check('the unlinked number no longer finds the suspended record and enrols afresh', orphan.status === 'issued' && withRecord(orphan).residentId !== typo.residentId);
}

(async () => {
  console.log('\n== Identity links (ORCS §11) ==');
  await registryAlone();
  await throughTheService();
  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
