/* eslint-disable no-console */
/**
 * Residency anchored to an address, for the jurisdictions where that is what residency means.
 *
 * The property this file protects is that the anchor is a JURISDICTION'S CHOICE and that
 * choosing one does not change the other. A unit-anchored deployment must behave exactly as it
 * did before this existed -- that is most of the world, and all of the deployments that came
 * before -- while an address-anchored one must actually be stricter, not merely differently
 * worded.
 */
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { addressKey, addressesMatch } from '../src/core/proofing/address';
import { evaluateResidence } from '../src/core/proofing/residence';

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
const ADDRESS = { lines: ['12 Ahmadu Bello Way'], postalCode: '800001', adminUnit: 'KT' };

function config(issuerDid: string, anchor: 'unit' | 'address'): CountryConfig {
  return parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Example',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: {
      minAssurance: 'verified',
      proofOfResidence: 'attestation',
      residence: {
        required: true,
        targetLevel: 'RAL2',
        acceptedMethods: ['authority_attestation'],
        unitMatchRequired: true,
        anchor,
      },
    },
    credential: {
      issuerDid,
      issuerName: 'Example Residency Authority',
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  });
}

async function main() {
  console.log('\n== residency anchored to a unit, or to an address ==\n');

  console.log('the comparison key is naive, and says so:');
  check('capitalisation is noise', addressKey({ lines: ['12 Ahmadu Bello Way'] }) === addressKey({ lines: ['12 AHMADU BELLO WAY'] }));
  check('punctuation and double spaces are noise', addressesMatch({ lines: ['12, Ahmadu  Bello Way.'] }, { lines: ['12 Ahmadu Bello Way'] }));
  check('an abbreviation is NOT resolved — that is a jurisdiction judgement', !addressesMatch({ lines: ['12 Ahmadu Bello Way'] }, { lines: ['12 Ahmadu Bello Wy'] }));
  check('a different door does not match', !addressesMatch({ lines: ['12 Ahmadu Bello Way'] }, { lines: ['14 Ahmadu Bello Way'] }));
  check('an empty address matches nothing, including another empty one', !addressesMatch({ lines: [''] }, { lines: ['  '] }));
  check('a missing address matches nothing', !addressesMatch(undefined, { lines: ['12 Ahmadu Bello Way'] }));
  check(
    'an informal descriptor is a first-class address',
    addressesMatch(
      { lines: ['third compound past the borehole, Rigasa ward'] },
      { lines: ['Third compound past the borehole, Rigasa ward'] },
    ),
  );

  console.log('\nunit anchoring is untouched by any of this:');
  const unitOnly = evaluateResidence(
    { required: true, targetLevel: 'RAL2', acceptedMethods: ['authority_attestation'], unitMatchRequired: true, acceptFoundationalResidence: false },
    [{ method: 'authority_attestation', adminUnit: 'KT', reportedUnit: 'Katsina' }],
    'KT',
    new Date().toISOString(),
  );
  check('evidence with no address still satisfies a unit-anchored policy', unitOnly.satisfied);
  check('  and reaches its level', unitOnly.level === 'RAL2');

  console.log('\naddress anchoring is STRICTER, not merely different:');
  const policy = { required: true, targetLevel: 'RAL2' as const, acceptedMethods: ['authority_attestation' as const], unitMatchRequired: true, acceptFoundationalResidence: false, anchor: 'address' as const };
  const now = new Date().toISOString();
  const noAddressOnEvidence = evaluateResidence(policy, [{ method: 'authority_attestation', adminUnit: 'KT' }], 'KT', now, ADDRESS);
  check('the same unit-only evidence NO LONGER satisfies it', !noAddressOnEvidence.satisfied);
  const wrongAddress = evaluateResidence(policy, [{ method: 'authority_attestation', adminUnit: 'KT', address: { lines: ['14 Ahmadu Bello Way'] } }], 'KT', now, ADDRESS);
  check('evidence for a different address does not satisfy it', !wrongAddress.satisfied);
  const rightAddress = evaluateResidence(policy, [{ method: 'authority_attestation', adminUnit: 'KT', address: ADDRESS }], 'KT', now, ADDRESS);
  check('evidence for the claimed address does', rightAddress.satisfied);
  check('  and the achieved residence names it', addressesMatch(rightAddress.address, ADDRESS));
  const rightAddressWrongUnit = evaluateResidence(policy, [{ method: 'authority_attestation', adminUnit: 'ZZ', address: ADDRESS }], 'KT', now, ADDRESS);
  check('the unit must STILL agree — an address alone is not enough', !rightAddressWrongUnit.satisfied);

  console.log('\nend to end, through the real service:');
  const key = await KeyStore.generate('anchor-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const build = () => new ResidencyService(new ProviderRegistry('anchor-pepper'), new VcIssuer(key), new InMemoryStore(), () => 'https://example/status/ng.json');

  const unitCfg = config(issuerDid, 'unit');
  const unitIssue = await build().issue(unitCfg, {
    countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KT' }],
  });
  check('a unit-anchored jurisdiction issues with no address at all', unitIssue.status === 'issued', unitIssue.status === 'rejected' ? unitIssue.reason : '');

  const addrCfg = config(issuerDid, 'address');
  const missing = await build().issue(addrCfg, {
    countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KT', address: ADDRESS }],
  });
  check('an address-anchored one refuses when no address is claimed', missing.status === 'rejected');
  check('  naming what is missing, not a generic residence failure',
    missing.status === 'rejected' && missing.reason === 'RESIDENCE_ADDRESS_REQUIRED', missing.status === 'rejected' ? missing.reason : '');

  const issued = await build().issue(addrCfg, {
    countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN },
    binding: { method: 'attended_comparison' },
    address: ADDRESS,
    residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KT', address: ADDRESS }],
  });
  check('and issues once the address is claimed and attested', issued.status === 'issued', issued.status === 'rejected' ? issued.reason : '');
  check('  the record anchors to the address', issued.status === 'issued' && addressesMatch(issued.record.residence.address, ADDRESS));

  console.log('\nerasure destroys the address, not just the name:');
  {
    const store = new InMemoryStore();
    const svc = new ResidencyService(new ProviderRegistry('p'), new VcIssuer(key), store, () => 'u');
    const r = await svc.issue(addrCfg, {
      countryCode: 'NG', subnationalUnit: 'KT', identifiers: { nin: NIN },
      binding: { method: 'attended_comparison' },
      address: ADDRESS,
      residenceEvidence: [{ method: 'authority_attestation', reportedUnit: 'KT', address: ADDRESS }],
    });
    if (r.status !== 'issued') throw new Error('setup failed: ' + (r.status === 'rejected' ? r.reason : r.status));
    const erased = await store.erase(r.residentId, 'tombstone-1', new Date());
    check('the name is gone', !erased?.person.fullName);
    check('  and so is the address — erasure must not keep the door', !erased?.residence.address);
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});