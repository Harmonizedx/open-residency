// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Credential delivery: the step between issued and in the holder's hands.
 *
 * The property this file protects is that a deployment which hands over at the desk changes
 * nothing -- no delivery store, `activateOn: issue`, credential ACTIVE on issue as it always
 * was -- while a deployment with a collection step gets exactly the gap it asked to see: the
 * credential waits in ISSUED, a recorded delivery activates it through the ordinary
 * transition, a failed attempt does not, and the counts come out by channel and status with
 * no identifier near them. Second property: an ISSUED credential still verifies.
 */
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { TrustedIssuer, VcVerifier } from '../src/core/credentials/vc-verifier';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { buildDefaultAssuranceRegistry } from '../src/core/assurance/profiles';
import {
  InMemoryDeliveryStore,
  countDeliveries,
  isDeliveredStatus,
  latestDelivery,
} from '../src/core/credentials/delivery';

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

const NIN = '12345678950';

function config(issuerDid: string, activateOn: 'issue' | 'first_delivery'): CountryConfig {
  return parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Example',
    defaultSubnationalUnit: 'KD',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid,
      issuerName: 'Example Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
      activateOn,
    },
    subnationalUnits: [{ code: 'KD', name: 'Kaduna', parent: 'NG', level: 'state', iso3166_2: 'NG-KD' }],
  });
}

async function main() {
  console.log('\n== credential delivery ==\n');

  console.log('pure helpers:');
  check('delivered and collected both count as delivery', isDeliveredStatus('delivered') && isDeliveredStatus('collected'));
  check('pending and failed do not', !isDeliveredStatus('pending') && !isDeliveredStatus('failed'));
  const sample = [
    { id: '1', residentId: 'r', countryCode: 'NG', channel: 'sms_link' as const, status: 'pending' as const, at: '2026-01-01T00:00:00.000Z' },
    { id: '2', residentId: 'r', countryCode: 'NG', channel: 'agent_handover' as const, status: 'failed' as const, at: '2026-01-02T00:00:00.000Z' },
    { id: '3', residentId: 'r', countryCode: 'NG', channel: 'agent_handover' as const, status: 'delivered' as const, at: '2026-01-03T00:00:00.000Z' },
  ];
  const c = countDeliveries(sample);
  check('counts fold by channel then status', c.agent_handover?.failed === 1 && c.agent_handover?.delivered === 1 && c.sms_link?.pending === 1);
  check('the latest event is by time, not by order', latestDelivery([sample[2], sample[0], sample[1]])?.id === '3');

  const key = await KeyStore.generate('delivery-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const build = (deliveries?: InMemoryDeliveryStore) => {
    const store = new InMemoryStore();
    const svc = new ResidencyService(
      new ProviderRegistry('delivery-pepper'),
      new VcIssuer(key),
      store,
      () => 'https://example/status/ng.json',
      undefined,
      buildDefaultAssuranceRegistry(),
      undefined,
      undefined,
      deliveries,
    );
    return { store, svc };
  };
  const enrol = (svc: ResidencyService, cfg: CountryConfig) =>
    svc.issue(cfg, {
      countryCode: 'NG', subnationalUnit: 'KD', identifiers: { nin: NIN },
      binding: { method: 'attended_comparison' },
      residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KD' }],
    });

  console.log('\nnothing changes for a deployment that hands over at the desk:');
  {
    const { svc } = build();
    const cfg = config(issuerDid, 'issue');
    const r = await enrol(svc, cfg);
    check('issues', r.status === 'issued', r.status === 'rejected' ? r.reason : '');
    if (r.status === 'issued') {
      check('  no status is written at issue, exactly as before', r.record.credentialStatus === undefined);
      check('  and it reads back ACTIVE', (await svc.credentialStatusFor(cfg, r.residentId))?.status === 'ACTIVE');
      const rec = await svc.recordDelivery(cfg, r.residentId, { channel: 'paper', status: 'delivered', by: 'operator:desk' });
      check('  recording a delivery without a store says so rather than pretending', !rec.ok && rec.reason === 'DELIVERY_STORE_NOT_CONFIGURED');
      check('  and the list is empty', (await svc.deliveriesFor(r.residentId)).length === 0);
    }
  }

  console.log('\nwith a store but the default activation, deliveries are recorded and nothing else moves:');
  {
    const deliveries = new InMemoryDeliveryStore();
    const { svc } = build(deliveries);
    const cfg = config(issuerDid, 'issue');
    const r = await enrol(svc, cfg);
    if (r.status !== 'issued') throw new Error('setup failed');
    const rec = await svc.recordDelivery(cfg, r.residentId, { channel: 'agent_handover', status: 'delivered', by: 'operator:field', evidenceRef: 'batch:7' });
    check('the event is recorded with its evidence', rec.ok && rec.event.channel === 'agent_handover' && rec.event.evidenceRef === 'batch:7' && rec.event.credentialId === r.record.credentialId);
    check('  nothing was activated, because nothing was waiting', rec.ok && rec.activated === false);
    check('  status is still ACTIVE', (await svc.credentialStatusFor(cfg, r.residentId))?.status === 'ACTIVE');
  }

  console.log('\nactivate on first delivery:');
  {
    const deliveries = new InMemoryDeliveryStore();
    const { svc } = build(deliveries);
    const cfg = config(issuerDid, 'first_delivery');
    const r = await enrol(svc, cfg);
    if (r.status !== 'issued') throw new Error('setup failed: ' + (r.status === 'rejected' ? r.reason : r.status));
    check('the credential is ISSUED, not ACTIVE, on issue', r.record.credentialStatus?.status === 'ISSUED');
    check('  and reads back ISSUED', (await svc.credentialStatusFor(cfg, r.residentId))?.status === 'ISSUED');

    const trusted: TrustedIssuer = { did: issuerDid, publicJwks: [key.publicJwk], statusLists: {} } as TrustedIssuer;
    const verifier = new VcVerifier(new Map([[issuerDid, trusted]]));
    const verified = await verifier.verify(r.credentialJwt, { offline: true });
    check('  an ISSUED credential still verifies -- delivery is bookkeeping, not a holder condition', verified.valid === true, JSON.stringify(verified).slice(0, 160));

    const pending = await svc.recordDelivery(cfg, r.residentId, { channel: 'sms_link', status: 'pending', by: 'operator:desk', evidenceRef: 'msg:1' });
    check('a pending dispatch is recorded and does not activate', pending.ok && !pending.activated && pending.credentialStatus?.status === 'ISSUED');
    const failedNoReason = await svc.recordDelivery(cfg, r.residentId, { channel: 'agent_handover', status: 'failed', by: 'operator:field' });
    check('a failure without a reason is refused by name', !failedNoReason.ok && failedNoReason.reason === 'FAILURE_REASON_REQUIRED_FOR_FAILED');
    const failed = await svc.recordDelivery(cfg, r.residentId, { channel: 'agent_handover', status: 'failed', by: 'operator:field', failureReason: 'not at home' });
    check('a failed attempt is recorded and does not activate', failed.ok && !failed.activated && failed.credentialStatus?.status === 'ISSUED');
    const delivered = await svc.recordDelivery(cfg, r.residentId, { channel: 'agent_handover', status: 'delivered', by: 'operator:field', evidenceRef: 'slip:42' });
    check('the first delivery activates the credential', delivered.ok && delivered.activated === true && delivered.credentialStatus?.status === 'ACTIVE');
    check('  through the ordinary transition, naming the delivery and the operator',
      delivered.ok && delivered.credentialStatus?.reason === 'DELIVERED_agent_handover' && delivered.credentialStatus?.authority === 'operator:field');
    const again = await svc.recordDelivery(cfg, r.residentId, { channel: 'paper', status: 'delivered', by: 'operator:desk' });
    check('a second delivery is recorded and activates nothing further', again.ok && again.activated === false && again.credentialStatus?.status === 'ACTIVE');
    const events = await svc.deliveriesFor(r.residentId);
    check('every attempt is on the record, oldest first', events.length === 4 && events.map((e) => e.status).join(',') === 'pending,failed,delivered,delivered');
    const counts = await deliveries.counts('NG');
    check('counts by channel and status carry no identifier', JSON.stringify(counts).includes('"delivered":1') && !JSON.stringify(counts).includes(r.residentId));

    const unknown = await svc.recordDelivery(cfg, 'KD-NOPE-0000-0', { channel: 'paper', status: 'delivered' });
    check('an unknown resident is refused by name', !unknown.ok && unknown.reason === 'UNKNOWN_RESIDENT');
  }

  console.log('\nthe wallet path records its own collection:');
  {
    const deliveries = new InMemoryDeliveryStore();
    const { svc } = build(deliveries);
    const cfg = config(issuerDid, 'first_delivery');
    const r = await enrol(svc, cfg);
    if (r.status !== 'issued') throw new Error('setup failed');
    const holderKey = await KeyStore.generate('holder');
    const minted = await svc.mintForHolder(cfg, r.record, didKeyFromJwk(holderKey.publicJwk), 'jwt_vc_json');
    const events = await svc.deliveriesFor(r.residentId);
    check('minting into a wallet records a collection over wallet_oid4vci', events.length === 1 && events[0].channel === 'wallet_oid4vci' && events[0].status === 'collected');
    check('  attributed to the channel, never to the holder\'s key', events[0].by === 'wallet' && !JSON.stringify(events[0]).includes('did:key'));
    check('  naming the minted credential', events[0].credentialId === minted.credentialId);
    check('  and the credential is now ACTIVE', (await svc.credentialStatusFor(cfg, r.residentId))?.status === 'ACTIVE');
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
