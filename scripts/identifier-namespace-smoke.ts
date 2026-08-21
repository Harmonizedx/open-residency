/* eslint-disable no-console */
/**
 * A subject reference is namespaced by the IDENTIFIER, not by the route it arrived through.
 *
 * The property this protects is one an agency running both a desk network and an online
 * channel depends on: the same person, reaching the register by two doors, is one record.
 * Before this, a resident enrolled at a desk through a NIN gateway and the same resident
 * returning online through an OIDC provider that released the same NIN produced two
 * references -- permanently unmergeable, since the reference is one-way and no identity-link
 * lifecycle exists to correct it.
 *
 * The namespace still has a job, and this file holds it: two DIFFERENT national schemes must
 * not collide. A NIN and an Aadhaar number are both digit strings.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tokenizeSubject, identifierNamespace } from '../src/core/foundational/util';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';

let pass = 0;
let fail = 0;
const check = (n: string, c: boolean, d?: string) => {
  if (c) { pass++; console.log(`  ✓ ${n}`); }
  else { fail++; console.log(`  ✗ ${n}${d ? `\n      ${d}` : ''}`); }
};

const NIN = '12345678901';
const PEPPER = 'one-deployment-pepper';
const ref = (code: string, identifierType?: string, raw = NIN) =>
  tokenizeSubject(identifierNamespace({ code, identifierType }), raw, PEPPER);

async function main() {
  console.log('\n== subject references are namespaced by the identifier ==\n');

  console.log('two routes to the same identifier reconcile:');
  check('desk (NG_NIN) and online (OIDC) agree when both declare NIN',
    ref('NG_NIN', 'NIN') === ref('OIDC', 'NIN'));
  check('  a third route agrees too', ref('MOSIP_IDA', 'NIN') === ref('NG_NIN', 'NIN'));
  check('  and the namespace is the identifier, not the provider',
    ref('OIDC', 'NIN').startsWith('nin:'));

  console.log('\ndifferent identifier schemes still cannot collide:');
  check('NIN and AADHAAR differ even on identical digits',
    ref('NG_NIN', 'NIN') !== ref('IN_AADHAAR', 'AADHAAR'));
  check('  which is what the namespace is FOR', ref('IN_AADHAAR', 'AADHAAR').startsWith('aadhaar:'));

  console.log('\ndifferent people never collide:');
  check('two NINs differ', ref('NG_NIN', 'NIN') !== ref('NG_NIN', 'NIN', '99999999999'));

  console.log('\nthis is additive — nothing already written changes value:');
  check('a provider declaring no identifierType keeps the provider namespace',
    ref('NG_NIN') === tokenizeSubject('NG_NIN', NIN, PEPPER));
  check('  and still differs from one that declares NIN',
    ref('NG_NIN') !== ref('NG_NIN', 'NIN'));
  check('an empty identifierType falls back rather than making an empty namespace',
    ref('NG_NIN', '   ') === ref('NG_NIN'));

  console.log('\nthe deployment pepper still isolates deployments:');
  check('the same identifier differs across deployments',
    tokenizeSubject('NIN', NIN, 'pepper-a') !== tokenizeSubject('NIN', NIN, 'pepper-b'));

  console.log('\nconfig accepts it, and does not require it:');
  const base = {
    countryCode: 'NG', countryName: 'Nigeria', defaultSubnationalUnit: 'KT',
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: { issuerDid: 'did:web:x', issuerName: 'X', type: 'StateResidencyCredential', validityDays: 365, context: ['https://www.w3.org/ns/credentials/v2'] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  };
  const withType = parseCountryConfig({ ...base, foundational: { provider: 'NG_NIN', identifierType: 'NIN', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' } });
  check('a config may declare an identifierType', withType.foundational.identifierType === 'NIN');
  const without = parseCountryConfig({ ...base, foundational: { provider: 'NG_NIN', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' } });
  check('  and may omit it', without.foundational.identifierType === undefined);
  let rejected = false;
  try { parseCountryConfig({ ...base, foundational: { provider: 'NG_NIN', identifierType: '', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' } }); }
  catch { rejected = true; }
  check('  an empty declared type is refused, not silently ignored', rejected);

  // ---------------------------------------------------------------------------
  // The property, end to end. Everything above proves the hash agrees; only this
  // proves a REGISTER reconciles -- which is the capability, and the G-01 lesson:
  // a structural assertion shows a constraint is gone, an end-to-end one shows a
  // capability exists.
  // ---------------------------------------------------------------------------
  console.log('\nend to end: the same person, two different providers, ONE record:');

  const SHARED_NIN = '12345678902'; // MOCK matches an even last digit
  const dir = mkdtempSync(join(tmpdir(), 'ors-idns-'));
  const csv = join(dir, 'register.csv');
  writeFileSync(csv, `national_id,first_name,last_name\n${SHARED_NIN},Amina,Bello\n`);

  const key = await KeyStore.generate('idns-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const e2eBase = {
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid, issuerName: 'Katsina', type: 'StateResidencyCredential',
      validityDays: 365, context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  };

  // Two genuinely different adapters, both declaring the identifier is a NIN.
  const deskCfg: CountryConfig = parseCountryConfig({
    ...e2eBase,
    foundational: {
      provider: 'MOCK', identifierType: 'NIN',
      inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified',
    },
  });
  const onlineCfg: CountryConfig = parseCountryConfig({
    ...e2eBase,
    foundational: {
      provider: 'IMPORT', identifierType: 'NIN',
      dataset: { path: csv, format: 'csv', keyField: 'national_id', identifierKey: 'nin' },
      inputs: [{ key: 'nin', label: 'NIN' }],
      responseMapping: { givenName: 'first_name', familyName: 'last_name' },
      assuranceOnSuccess: 'verified',
      extra: { subjectSourcePath: 'national_id' },
    },
  });

  const store = new InMemoryStore();
  const svc = new ResidencyService(
    new ProviderRegistry('one-deployment-pepper'), new VcIssuer(key), store,
    () => 'https://id.katsina.gov.ng/status/ng.json',
  );
  const req = { countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: SHARED_NIN } };

  const atDesk = await svc.issue(deskCfg, req);
  check('enrolled at the desk (MOCK)', atDesk.status === 'issued',
    atDesk.status === 'rejected' ? atDesk.reason : atDesk.status);

  const online = await svc.issue(onlineCfg, req);
  check('returning online (IMPORT) is RECOGNISED, not enrolled again',
    online.status === 'exists', online.status === 'rejected' ? online.reason : online.status);
  check('  the register holds ONE record for this person',
    (await store.list({ countryCode: 'NG' })).total === 1);
  check('  and it is the same record',
    online.status === 'exists' && atDesk.status === 'issued' &&
      online.residentId === atDesk.residentId);

  // The counterfactual: without the declaration, the same two routes duplicate.
  const deskNoType = parseCountryConfig({ ...e2eBase, foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' } });
  const onlineNoType = parseCountryConfig({ ...e2eBase, foundational: { ...(onlineCfg.foundational as any), identifierType: undefined } });
  const store2 = new InMemoryStore();
  const svc2 = new ResidencyService(new ProviderRegistry('p2'), new VcIssuer(key), store2, () => 'u');
  await svc2.issue(deskNoType, req);
  const dup = await svc2.issue(onlineNoType, req);
  check('WITHOUT the declaration the same two routes still duplicate', dup.status === 'issued');
  check('  leaving two records — which is what this change prevents',
    (await store2.list({ countryCode: 'NG' })).total === 2);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
