/* eslint-disable no-console */
/**
 * The credential's ORCS §10 lifecycle, and the four things a revocation must preserve.
 *
 * The rule this file protects is that a terminal decision is REFUSED when it cannot be
 * recorded properly, rather than written with blanks. A revocation with no reason, no named
 * authority or no appeal path is what `revoke()` produced for the whole life of this project:
 * a set bit, indistinguishable from any other set bit, that no citizen could contest and no
 * auditor could attribute.
 */
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import {
  CredentialStatus,
  applyCredentialTransition,
  backfilledCredentialStatus,
  canTransitionCredential,
  isTerminalCredentialStatus,
} from '../src/core/credentials/credential-lifecycle';

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

const ALL: CredentialStatus[] = ['ISSUED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED', 'REPLACED'];

// The MOCK provider matches an identifier whose last digit is even.
const NIN_A = '12345678930';
const NIN_B = '12345678932';
const NIN_C = '12345678934';

function config(issuerDid: string, over: Record<string, unknown> = {}): CountryConfig {
  return parseCountryConfig({
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
      ...over,
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });
}

async function main() {
  console.log('\n== credential lifecycle (ORCS §10) ==\n');

  console.log('the state machine follows §10:');
  check('ACTIVE can be suspended', canTransitionCredential('ACTIVE', 'SUSPENDED'));
  check('SUSPENDED can be reinstated', canTransitionCredential('SUSPENDED', 'ACTIVE'));
  check('ACTIVE can be revoked', canTransitionCredential('ACTIVE', 'REVOKED'));
  check('ACTIVE can be replaced', canTransitionCredential('ACTIVE', 'REPLACED'));
  check('REVOKED is terminal', ALL.every((s) => !canTransitionCredential('REVOKED', s)));
  check('REPLACED is terminal', ALL.every((s) => !canTransitionCredential('REPLACED', s)));
  check('EXPIRED is terminal', ALL.every((s) => !canTransitionCredential('EXPIRED', s)));
  check(
    'the terminal set is exactly REVOKED, EXPIRED, REPLACED',
    ALL.filter(isTerminalCredentialStatus).join() === 'REVOKED,EXPIRED,REPLACED',
  );

  console.log('\nORCS §10: revocation preserves all four, or is refused:');
  const active = { status: 'ACTIVE' as CredentialStatus, at: '2026-01-01T00:00:00.000Z' };
  check(
    'no reason -> refused',
    !applyCredentialTransition(active, { to: 'REVOKED', authority: 'op', appealPath: 'office' }).ok,
  );
  check(
    'no authority -> refused',
    !applyCredentialTransition(active, { to: 'REVOKED', reason: 'fraud', appealPath: 'office' }).ok,
  );
  check(
    'no appeal path -> refused',
    !applyCredentialTransition(active, { to: 'REVOKED', reason: 'fraud', authority: 'op' }).ok,
  );
  const full = applyCredentialTransition(active, {
    to: 'REVOKED',
    reason: 'Issued in error',
    authority: 'operator:Registrar',
    appealPath: 'Appeals Office, 30 days',
    at: '2026-08-16T09:00:00.000Z',
  });
  check('all four present -> accepted', full.ok);
  if (full.ok) {
    check('  reason preserved', full.record.reason === 'Issued in error');
    check('  authority preserved', full.record.authority === 'operator:Registrar');
    check('  timestamp preserved', full.record.at === '2026-08-16T09:00:00.000Z');
    check('  appeal path preserved', full.record.appealPath === 'Appeals Office, 30 days');
    check('  the revocation bit is published', full.publish.some((p) => p.purpose === 'revocation' && p.set));
    check('  and any suspension bit is cleared', full.publish.some((p) => p.purpose === 'suspension' && !p.set));
  }

  console.log('\nreplacement points at its successor (§10):');
  check(
    'no supersededBy -> refused',
    !applyCredentialTransition(active, { to: 'REPLACED', reason: 'reissued', authority: 'op' }).ok,
  );
  const replaced = applyCredentialTransition(active, {
    to: 'REPLACED',
    reason: 'reissued after device loss',
    authority: 'op',
    supersededBy: 'urn:uuid:next',
  });
  check('with supersededBy -> accepted', replaced.ok);
  check('  the pointer is preserved', replaced.ok && replaced.record.supersededBy === 'urn:uuid:next');

  console.log('\nsuspension is attributable and reversible:');
  check(
    'suspending without an authority is refused',
    !applyCredentialTransition(active, { to: 'SUSPENDED', reason: 'lost' }).ok,
  );
  const susp = applyCredentialTransition(active, { to: 'SUSPENDED', authority: 'op', reason: 'lost' });
  check('suspending with one is accepted', susp.ok);
  check('  it sets the SUSPENSION bit, not the revocation bit',
    susp.ok && susp.publish.length === 1 && susp.publish[0].purpose === 'suspension' && susp.publish[0].set);
  const back = susp.ok ? applyCredentialTransition(susp.record, { to: 'ACTIVE', authority: 'op' }) : null;
  check('  reinstating clears it', !!back?.ok && back.publish.some((p) => p.purpose === 'suspension' && !p.set));

  console.log('\npre-lifecycle rows are read from the only evidence they carry:');
  const wasNotRevoked = backfilledCredentialStatus(false, '2020-01-01T00:00:00.000Z');
  check('an unset bit reads as ACTIVE', wasNotRevoked.status === 'ACTIVE');
  const wasRevoked = backfilledCredentialStatus(true, '2020-01-01T00:00:00.000Z');
  check('a set bit reads as REVOKED', wasRevoked.status === 'REVOKED');
  check('  and says the reason is not recoverable', /not recoverable/i.test(wasRevoked.reason ?? ''));
  check('  rather than inventing one', wasRevoked.authority === 'migration:pre-lifecycle-record');

  // ---------------------------------------------------------------------------
  console.log('\nend to end, through the real service and its status lists:');
  const key = await KeyStore.generate('cred-lifecycle-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const cfg = config(issuerDid, { appealPath: 'Katsina Appeals Office, within 30 days' });
  const store = new InMemoryStore();
  const svc = new ResidencyService(
    new ProviderRegistry('cred-pepper'),
    new VcIssuer(key),
    store,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );

  const issued = await svc.issue(cfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN_A } });
  check('a credential issues', issued.status === 'issued');
  const id = issued.status === 'issued' ? issued.residentId : '';
  const idx = issued.status === 'issued' ? issued.record.statusListIndex : -1;

  const s1 = await svc.transitionCredential(cfg, id, { to: 'SUSPENDED', authority: 'operator:A', reason: 'reported lost' });
  check('it can be suspended', s1.ok);
  check('  the SUSPENSION list has the bit', (await store.loadStatusList('NG', 'suspension')).isRevoked(idx));
  check('  the REVOCATION list does NOT', !(await store.loadStatusList('NG', 'revocation')).isRevoked(idx));

  const s2 = await svc.transitionCredential(cfg, id, { to: 'ACTIVE', authority: 'operator:A' });
  check('it can be reinstated', s2.ok);
  check('  the suspension bit clears', !(await store.loadStatusList('NG', 'suspension')).isRevoked(idx));

  const s3 = await svc.transitionCredential(cfg, id, {
    to: 'REVOKED',
    authority: 'operator:Registrar',
    reason: 'Issued in error',
    appealPath: cfg.credential.appealPath,
  });
  check('it can be revoked', s3.ok);
  check('  the revocation bit is set', (await store.loadStatusList('NG', 'revocation')).isRevoked(idx));
  const status = await svc.credentialStatusFor(cfg, id);
  check('  the register can say WHY', status?.reason === 'Issued in error');
  check('  and by WHOSE authority', status?.authority === 'operator:Registrar');
  check('  and WHERE to appeal', status?.appealPath === 'Katsina Appeals Office, within 30 days');
  check('  a revoked credential cannot be revoked again', !(await svc.transitionCredential(cfg, id, {
    to: 'REVOKED', authority: 'op', reason: 'again', appealPath: 'x',
  })).ok);

  console.log('\nthe legacy revoke() still works, and now records something:');
  const legacyCfg = config(issuerDid, { appealPath: 'Legacy appeals desk' });
  const l = await svc.issue(legacyCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN_B } });
  const lid = l.status === 'issued' ? l.residentId : '';
  check('revoke() returns true', await svc.revoke(legacyCfg, lid));
  const lstatus = await svc.credentialStatusFor(legacyCfg, lid);
  check('  it records REVOKED', lstatus?.status === 'REVOKED');
  check('  with the configured appeal path', lstatus?.appealPath === 'Legacy appeals desk');
  check('  and names the issuing authority', lstatus?.authority === 'Katsina State Residency Authority');

  console.log('\na deployment that declares no appeal path says so, rather than leaving it blank:');
  const bareCfg = config(issuerDid);
  const b = await svc.issue(bareCfg, { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN_C } });
  const bid = b.status === 'issued' ? b.residentId : '';
  await svc.revoke(bareCfg, bid);
  const bstatus = await svc.credentialStatusFor(bareCfg, bid);
  check('the appeal path is present', !!bstatus?.appealPath);
  check('  and states that none was published', /No appeal path published/i.test(bstatus?.appealPath ?? ''));

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});