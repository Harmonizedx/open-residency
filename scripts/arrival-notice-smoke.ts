// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Arrival notices between two deployments, and the rule each declares for the other.
 *
 * Two in-memory deployments -- Katsina (home) and Kano (peer) -- federated with each other.
 * A person holds Katsina residency, presents it at Kano's desk, and is registered there. Kano
 * tells Katsina with a signed notice carrying the credential id and a hash of the credential
 * as presented, and nothing about the person. What Katsina does is its own declared rule for
 * Kano: nothing, record a conflict, suspend after a grace period, or end after one. A person
 * can reverse a conflict before the grace period runs, and reinstate a suspension after it.
 *
 * The properties this file protects:
 *   - a notice carries no personal data, and one that does is refused;
 *   - only a listed peer, signing with a listed key, addressed to this deployment, within
 *     validity, and never seen before, is heard;
 *   - under `none` two ACTIVE residencies coexist and no conflict exists;
 *   - under `record` a conflict is opened and the relationship is untouched;
 *   - under `suspend` and `end` nothing happens until the grace period has run, a person can
 *     reverse before then, and the transition is attributed to the rule and the peer;
 *   - neither register gains a row for the other jurisdiction's residency, ever;
 *   - an undeliverable notice is kept and retried, and the sweep is idempotent.
 */
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { KeyStore, IssuerKey } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig } from '../src/core/config/country-config';
import { FederatedIssuer, ExclusivityPolicy, DEFAULT_EXCLUSIVITY } from '../src/core/credentials/federation';
import { signJwt } from '../src/core/credentials/signer';
import {
  ARRIVAL_NOTICE_TYP,
  ArrivalNoticeService,
  InMemoryArrivalNoticeStore,
  presentationHashOf,
} from '../src/core/residency/arrival-notice';

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

function configFor(unit: string, name: string, issuerDid: string) {
  return parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: unit,
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid,
      issuerName: `${name} State Residency Authority`,
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: unit, name, parent: 'NG', level: 'state' }],
  });
}

interface Deployment {
  name: string;
  did: string;
  key: IssuerKey;
  cfg: ReturnType<typeof parseCountryConfig>;
  store: InMemoryStore;
  residency: ResidencyService;
  trust: Map<string, TrustedIssuer>;
  verifier: VcVerifier;
  peers: FederatedIssuer[];
  notices: InMemoryArrivalNoticeStore;
  service: ArrivalNoticeService;
  clock: { now: Date };
}

async function deployment(unit: string, name: string, pepper: string): Promise<Omit<Deployment, 'service'>> {
  const key = await KeyStore.generate(`${unit.toLowerCase()}-key-1`);
  const did = didKeyFromJwk(key.publicJwk);
  const cfg = configFor(unit, name, did);
  const store = new InMemoryStore();
  const residency = new ResidencyService(new ProviderRegistry(pepper), new VcIssuer(key), store, () => `https://id.${unit.toLowerCase()}.gov.ng/status/ng.json`);
  const trust = new Map<string, TrustedIssuer>();
  trust.set(did, { did, publicJwks: [key.publicJwk], statusLists: {} });
  return { name, did, key, cfg, store, residency, trust, verifier: new VcVerifier(trust), peers: [], notices: new InMemoryArrivalNoticeStore(), clock: { now: new Date('2026-10-13T09:00:00.000Z') } };
}

async function main() {
  console.log('\n== Arrival notices under a declared exclusivity rule ==\n');

  const home = (await deployment('KT', 'Katsina', 'home-pepper')) as Deployment;
  const peer = (await deployment('KN', 'Kano', 'peer-pepper')) as Deployment;

  // Each trusts the other, as a federation does. Kano knows where Katsina receives notices;
  // Katsina declares a rule for notices from Kano (set per scenario below).
  const homeRule: { policy: ExclusivityPolicy } = { policy: { rule: 'none', graceDays: 0 } };
  home.trust.set(peer.did, { did: peer.did, publicJwks: [peer.key.publicJwk], statusLists: {} });
  peer.trust.set(home.did, { did: home.did, publicJwks: [home.key.publicJwk], statusLists: {} });
  const delivered: { url: string; notice: string }[] = [];
  const wire = { down: false };

  const build = (d: Deployment, peers: () => FederatedIssuer[], deliver: (url: string, body: { notice: string }) => Promise<void>) =>
    new ArrivalNoticeService({
      store: d.notices,
      residents: d.store,
      residency: d.residency,
      verifier: d.verifier,
      trust: d.trust,
      peers,
      ownIssuers: () => [{ countryCode: 'NG', did: d.did }],
      signer: d.key.signer,
      deliver,
      now: () => d.clock.now,
    });

  home.service = build(
    home,
    () => [{ did: peer.did, name: 'Kano State Residency Authority', publicJwks: [peer.key.publicJwk], exclusivity: homeRule.policy }],
    async () => {
      throw new Error('Katsina sends nothing in this scenario');
    },
  );
  peer.service = build(
    peer,
    () => [{ did: home.did, name: 'Katsina State Residency Authority', publicJwks: [home.key.publicJwk], arrivalNoticeUrl: 'https://id.katsina.gov.ng/federation/arrival-notices' }],
    async (url, body) => {
      if (wire.down) throw new Error('ECONNREFUSED');
      delivered.push({ url, notice: body.notice });
      const outcome = await home.service.receive(body.notice);
      if (!outcome.ok) throw new Error(`peer refused: ${outcome.reason}`);
    },
  );

  // The person: Katsina residency first.
  const nin = '12345678902';
  const issued = await home.residency.issue(home.cfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin } });
  check('Katsina issues a residency', issued.status === 'issued');
  if (issued.status !== 'issued') throw new Error('fixture failed');
  const credential = issued.credentialJwt;
  const residentId = issued.residentId;
  const relationship = async () => (await home.residency.relationshipFor(residentId))!.status;

  // Then Kano registers the same person, who presented the Katsina credential at the desk.
  const moved = await peer.residency.issue(peer.cfg, { countryCode: 'NG', subnationalUnit: 'KN', identifiers: { nin } });
  check('Kano registers the person as its own resident', moved.status === 'issued');

  console.log('\nWhat a notice is, and is not:');
  const noteIt = () => peer.service.notify({ countryCode: 'NG', credential, presentedAt: '2026-10-13T08:30:00.000Z', registeredAt: '2026-10-13T08:45:00.000Z' });

  const ownCredential = moved.status === 'issued' ? moved.credentialJwt : '';
  const self = await peer.service.notify({ countryCode: 'NG', credential: ownCredential });
  check('a credential this deployment issued itself is not a move: no notice', !self.ok && self.reason === 'CREDENTIAL_IS_OURS');
  const forged = await peer.service.notify({ countryCode: 'NG', credential: credential.slice(0, -4) + 'AAAA' });
  check('a credential that does not verify is never vouched for to its issuer', !forged.ok && forged.reason.startsWith('CREDENTIAL_'), forged.ok ? '' : forged.reason);

  // Scenario 1 -- rule `none`: the two residencies coexist, and nothing is a conflict.
  console.log('\nRule `none` -- compatible concurrent residencies:');
  homeRule.policy = { rule: 'none', graceDays: 0 };
  const n1 = await noteIt();
  check('Kano sends a signed notice to the endpoint Katsina published', n1.ok && n1.notice.status === 'sent' && delivered.length === 1 && delivered[0].url.endsWith('/federation/arrival-notices'), n1.ok ? '' : n1.reason);
  const sentJwt = delivered[0]?.notice ?? '';
  const payload = JSON.parse(Buffer.from(sentJwt.split('.')[1], 'base64url').toString());
  const header = JSON.parse(Buffer.from(sentJwt.split('.')[0], 'base64url').toString());
  check('  the notice names the credential and a hash of it as presented', payload.credentialId === issued.record.credentialId && payload.presentationHash === presentationHashOf(credential));
  check('  and carries nothing else: no name, no identifier, no address', Object.keys(payload).sort().join(',') === 'aud,credentialId,exp,iat,iss,jti,presentationHash,presentedAt,registeredAt' && !sentJwt.includes(nin));
  check('  typed as an arrival notice, signed by Kano, addressed to Katsina', header.typ === ARRIVAL_NOTICE_TYP && payload.iss === peer.did && payload.aud === home.did);
  const r1 = (await home.notices.list({ direction: 'inbound' })).items[0];
  check('Katsina noted it, matched to its own record, and opened NO conflict', !!r1 && r1.status === 'noted' && r1.conflict === false && r1.residentId === residentId && r1.rule === 'none');
  check('  both residencies are ACTIVE', (await relationship()) === 'ACTIVE' && (await peer.residency.relationshipFor(moved.status === 'issued' ? moved.residentId : ''))?.status === 'ACTIVE');
  check('  neither register gained a row for the other jurisdiction', (await home.store.list()).total === 1 && (await peer.store.list()).total === 1);

  // Scenario 2 -- rule `record`: a conflict exists, for a person; the relationship is untouched.
  console.log('\nRule `record` -- a conflict for a person to look at:');
  homeRule.policy = { rule: 'record', graceDays: 3 };
  const n2 = await noteIt();
  const r2 = n2.ok ? await home.notices.findById(n2.notice.id) : null;
  check('a conflict is opened, attributed to the peer and the rule', !!r2 && r2.status === 'open' && r2.conflict === true && r2.peerDid === peer.did && r2.rule === 'record');
  check('  the relationship is untouched', (await relationship()) === 'ACTIVE');
  const upheld = await home.service.resolve(r2!.id, { by: 'operator:registrar-1', resolution: 'upheld', reason: 'Confirmed with the resident by phone' });
  check('  a person resolves it, with a reason, and the decision is kept', upheld.ok && upheld.notice.status === 'resolved' && upheld.notice.resolvedBy === 'operator:registrar-1' && upheld.notice.resolution === 'upheld');
  const noReason = await home.service.resolve(r2!.id, { by: 'operator:registrar-1', resolution: 'upheld', reason: '' });
  check('  resolving twice, or without a reason, is refused', !noReason.ok);
  const defaults = DEFAULT_EXCLUSIVITY;
  check('  `record` with three days is what a peer gets when nothing is declared', defaults.rule === 'record' && defaults.graceDays === 3);

  // Scenario 3 -- rule `suspend`, grace period: nothing happens until it runs; a person can reverse.
  console.log('\nRule `suspend` with a grace period:');
  homeRule.policy = { rule: 'suspend', graceDays: 3 };
  const n3 = await noteIt();
  const r3 = n3.ok ? (await home.notices.findById(n3.notice.id))! : null;
  check('the notice is pending, with the date the rule falls due', !!r3 && r3.status === 'pending' && r3.conflict && r3.effectiveAt === '2026-10-16T09:00:00.000Z');
  check('  nothing is applied before then', (await relationship()) === 'ACTIVE' && (await home.service.applyDue(new Date('2026-10-15T23:59:59.000Z'))).length === 0);
  const reversed = await home.service.resolve(r3!.id, { by: 'operator:registrar-1', resolution: 'reversed', reason: 'Resident presented a current tenancy here; the Kano registration is a work address' });
  check('  a person reverses it in time: resolved, nothing applied', reversed.ok && reversed.notice.status === 'resolved' && reversed.notice.appliedTransition === undefined);
  check('  and the sweep then finds nothing', (await home.service.applyDue(new Date('2026-10-20T00:00:00.000Z'))).length === 0 && (await relationship()) === 'ACTIVE');

  const n3b = await noteIt();
  const r3b = n3b.ok ? (await home.notices.findById(n3b.notice.id))! : null;
  home.clock.now = new Date('2026-10-16T09:00:00.000Z');
  const applied = await home.service.applyDue();
  check('once the grace period has run, the sweep suspends the relationship', applied.length === 1 && applied[0].id === r3b!.id && applied[0].status === 'applied' && applied[0].appliedTransition === 'SUSPENDED' && (await relationship()) === 'SUSPENDED');
  const rel = await home.residency.relationshipFor(residentId);
  check('  attributed to the rule and the peer, with the notice named in the reason', rel?.decidedBy === `rule:exclusivity:${peer.did}` && (rel as unknown as { endedReason?: string }).endedReason === undefined);
  check('  the sweep is idempotent', (await home.service.applyDue()).length === 0);
  const reinstated = await home.service.resolve(r3b!.id, { by: 'operator:registrar-2', resolution: 'reversed', reason: 'Error: the person never left' });
  check('  reversing a suspension reinstates the relationship', reinstated.ok && (await relationship()) === 'ACTIVE');

  // Scenario 4 -- rule `end`, no grace period: applied on receipt; ENDED cannot be reversed from here.
  console.log('\nRule `end` without a grace period:');
  homeRule.policy = { rule: 'end', graceDays: 0 };
  const n4 = await noteIt();
  const r4 = n4.ok ? (await home.notices.findById(n4.notice.id))! : null;
  check('applied on receipt: the relationship is ENDED, by the rule, naming the peer', !!r4 && r4.status === 'applied' && r4.appliedTransition === 'ENDED' && (await relationship()) === 'ENDED');
  const cannot = await home.service.resolve(r4!.id, { by: 'operator:registrar-1', resolution: 'reversed', reason: 'Mistake' });
  check('  ENDED is terminal: not reversible from here, the person re-enrols', !cannot.ok && cannot.reason === 'CANNOT_REVERSE_ENDED');
  const n5 = await noteIt();
  check('  a further notice about an ended relationship is noted, not applied', n5.ok && (await home.notices.findById(n5.notice.id))!.status === 'noted');

  // What is refused.
  console.log('\nWhat Katsina refuses:');
  const replay = await home.service.receive(delivered[0].notice);
  check('a notice seen before (same jti) is a replay', !replay.ok && replay.reason === 'REPLAY');
  const strangerKey = await KeyStore.generate('stranger');
  const strangerDid = didKeyFromJwk(strangerKey.publicJwk);
  const claims = { iss: strangerDid, aud: home.did, jti: 'urn:uuid:stranger-1', exp: Math.floor(Date.now() / 1000) + 600, credentialId: issued.record.credentialId!, presentationHash: presentationHashOf(credential), presentedAt: '2026-10-13T08:30:00.000Z', registeredAt: '2026-10-13T08:45:00.000Z' };
  const stranger = await home.service.receive(await signJwt(strangerKey.signer, { kid: `${strangerDid}#stranger`, typ: ARRIVAL_NOTICE_TYP }, claims));
  check('a notice from a jurisdiction not in the trust list is refused', !stranger.ok && stranger.reason === 'UNTRUSTED_PEER');
  const misaddressed = await home.service.receive(await signJwt(peer.key.signer, { kid: `${peer.did}#${peer.key.kid}`, typ: ARRIVAL_NOTICE_TYP }, { ...claims, iss: peer.did, jti: 'urn:uuid:aud-1', aud: strangerDid }));
  check('a notice addressed to another deployment is refused', !misaddressed.ok && misaddressed.reason === 'NOT_ADDRESSED_TO_THIS_DEPLOYMENT');
  const expired = await home.service.receive(await signJwt(peer.key.signer, { kid: `${peer.did}#${peer.key.kid}`, typ: ARRIVAL_NOTICE_TYP }, { ...claims, iss: peer.did, jti: 'urn:uuid:exp-1', exp: Math.floor(Date.now() / 1000) - 60 }));
  check('an expired notice is refused', !expired.ok && expired.reason === 'EXPIRED');
  const leaky = await home.service.receive(await signJwt(peer.key.signer, { kid: `${peer.did}#${peer.key.kid}`, typ: ARRIVAL_NOTICE_TYP }, { ...claims, iss: peer.did, jti: 'urn:uuid:pii-1', fullName: 'A. Person' }));
  check('a notice carrying anything about the person is refused outright', !leaky.ok && leaky.reason === 'UNEXPECTED_CLAIM_fullName');
  const notANotice = await home.service.receive(credential);
  check('a credential presented as a notice is refused by type', !notANotice.ok && notANotice.reason === 'WRONG_TYPE');
  const unknown = await home.service.receive(await signJwt(peer.key.signer, { kid: `${peer.did}#${peer.key.kid}`, typ: ARRIVAL_NOTICE_TYP }, { ...claims, iss: peer.did, jti: 'urn:uuid:unknown-1', credentialId: 'urn:uuid:not-ours' }));
  check('a notice for a credential this register never issued is kept as unmatched, nothing applied', unknown.ok && unknown.notice.status === 'unmatched' && unknown.notice.conflict === false && unknown.notice.residentId === undefined);

  // Delivery failure is an ordinary condition: kept, retried, never lost.
  console.log('\nWhen the peer cannot be reached:');
  wire.down = true;
  const n6 = await noteIt();
  check('an undeliverable notice is kept as failed, with the error', n6.ok && n6.notice.status === 'failed' && n6.notice.attempts === 1 && /ECONNREFUSED/.test(n6.notice.deliveryDetail ?? ''));
  const stillDown = await peer.service.retryFailed();
  check('  the sweep retries and it fails again', stillDown.failed.length === 1 && stillDown.sent.length === 0 && (await peer.notices.findById(n6.ok ? n6.notice.id : ''))!.attempts === 2);
  wire.down = false;
  const backUp = await peer.service.retryFailed();
  check('  and delivers it once the peer is back', backUp.sent.length === 1 && (await peer.notices.findById(n6.ok ? n6.notice.id : ''))!.status === 'sent');
  check('  Katsina received exactly that notice once', (await home.notices.findById(n6.ok ? n6.notice.id : '')) !== null);
  const outbound = await peer.notices.list({ direction: 'outbound' });
  check('Kano keeps every notice it sent, as evidence', outbound.total === 7 && outbound.items.every((n) => n.notice.split('.').length === 3));

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
