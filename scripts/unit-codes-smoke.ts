// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Unit codes: a deployment's own key, ISO 3166-2 beside it, and reconciliation between them.
 *
 * The property this file protects is that a locality reported in one notation and a unit
 * declared in another still reconcile when they name the same place -- `NI` against `NG-NI` --
 * while nothing else is loosened: a name is still an exact match, an unknown locality is still
 * unmapped, and the value handed back is always the deployment's own `code`, never the
 * reported string. It also pins the start-up warning surface: an unassigned state code is
 * reported, a declared `iso3166_2` from another country is reported, and a ward is left alone.
 */
import { reconcileUnit } from '../src/core/proofing/residence';
import {
  canonicalUnitCode,
  isIso3166_2Shape,
  loadSubdivisionTable,
  unitCodeWarnings,
} from '../src/core/config/iso3166-2';
import { parseCountryConfig } from '../src/core/config/country-config';

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

console.log('canonical form');
check('bare suffix is unchanged', canonicalUnitCode('KT') === 'KT');
check('full ISO code drops this country\'s prefix', canonicalUnitCode('NG-NI', 'NG') === 'NI');
check('another country\'s prefix is kept', canonicalUnitCode('GH-NI', 'NG') === 'GH-NI');
check('with no country to check against, the prefix is kept', canonicalUnitCode('NG-NI') === 'NG-NI');
check('case and whitespace are normalised', canonicalUnitCode(' ng-kd ', 'ng') === 'KD');
check('a local scheme is left alone', canonicalUnitCode('ward-07', 'NG') === 'WARD-07');
check('shape test accepts CC-XXX', isIso3166_2Shape('NG-KD') && isIso3166_2Shape('ng-fc'));
check('shape test rejects a bare suffix and a long tail', !isIso3166_2Shape('KD') && !isIso3166_2Shape('NG-KADU'));

console.log('table');
const TABLES = 'config/iso3166-2';
const ng = loadSubdivisionTable(TABLES, 'NG');
check('Nigeria table ships as data under config/, not as code in the core', ng !== undefined);
check('36 states and the FCT', Object.keys(ng ?? {}).length === 37, String(Object.keys(ng ?? {}).length));
check('Kaduna is NG-KD', ng?.KD === 'Kaduna');
check('no table for a country we do not ship', loadSubdivisionTable(TABLES, 'XX') === undefined);

console.log('reconciliation');
const units = [
  { code: 'KT', name: 'Katsina', iso3166_2: 'NG-KT' },
  { code: 'KD', name: 'Kaduna', iso3166_2: 'NG-KD' },
  { code: 'NG-NI', name: 'Niger', iso3166_2: 'NG-NI' },
  { code: 'ZA', name: 'Zamfara' },
];
check('exact code still matches', reconcileUnit(units, 'KT', 'NG') === 'KT');
check('bare suffix reconciles to a unit declared in full ISO form', reconcileUnit(units, 'NI', 'NG') === 'NG-NI');
check('full ISO form reconciles to a unit declared bare', reconcileUnit(units, 'NG-KD', 'NG') === 'KD');
check('the value returned is the configured code, not the reported string', reconcileUnit(units, 'ng-ni', 'NG') === 'NG-NI');
check('declared iso3166_2 is matched even when code differs in form', reconcileUnit(units, 'NG-KT', 'NG') === 'KT');
check('a unit without iso3166_2 still reconciles by prefix tolerance', reconcileUnit(units, 'NG-ZA', 'NG') === 'ZA');
check('name match is exact, as before', reconcileUnit(units, 'kaduna', 'NG') === 'KD');
check('a near-name does not match', reconcileUnit(units, 'Kaduna State', 'NG') === undefined);
check('an unknown locality is unmapped', reconcileUnit(units, 'LA', 'NG') === undefined);
check('another country\'s identical suffix is not confused with ours', reconcileUnit(units, 'GH-NI', 'NG') === undefined);
check('without a country, only exact or full-code matches survive', reconcileUnit(units, 'NI') === undefined && reconcileUnit(units, 'NG-NI') === 'NG-NI');

console.log('warnings');
const w1 = unitCodeWarnings('NG', [
  { code: 'KT', level: 'state', iso3166_2: 'NG-KT' },
  { code: 'KD', level: 'state' },
  { code: 'XZ', level: 'state' },
  { code: 'QQ', level: 'state', iso3166_2: 'NG-QQ' },
  { code: 'AB', level: 'state', iso3166_2: 'GH-AB' },
  { code: 'WARD-07', level: 'ward' },
  { code: 'LG', level: 'lga' },
], ng);
check('a declared, assigned iso3166_2 is silent', !w1.some((w) => w.unitCode === 'KT'));
check('a bare state code in the table is silent', !w1.some((w) => w.unitCode === 'KD'));
check('an unassigned state code is reported', w1.some((w) => w.unitCode === 'XZ'));
check('an unassigned iso3166_2 is reported', w1.some((w) => w.unitCode === 'QQ' && /not assigned/.test(w.message)));
check('an iso3166_2 from another country is reported', w1.some((w) => w.unitCode === 'AB' && /does not belong/.test(w.message)));
check('a ward is not checked', !w1.some((w) => w.unitCode === 'WARD-07'));
check('an LGA is not checked', !w1.some((w) => w.unitCode === 'LG'));
check('no table, no warnings', unitCodeWarnings('XX', [{ code: 'ZZ', level: 'state' }], undefined).length === 0);

console.log('config schema');
let rejected = false;
try {
  parseCountryConfig({
    countryCode: 'NG',
    countryName: 'Example',
    defaultSubnationalUnit: 'KT',
    foundational: { provider: 'MOCK', assuranceOnSuccess: 'verified' },
    residency: { minAssurance: 'verified' },
    credential: { issuerDid: 'did:web:example.org', issuerName: 'Example', type: 'StateResidencyCredential', validityDays: 1, context: [] },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', level: 'state', iso3166_2: 'Katsina' }],
  });
} catch {
  rejected = true;
}
check('a malformed iso3166_2 is refused at load', rejected);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
