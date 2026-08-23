// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * The ORCS §8 Assurance Registry: governed profiles, §8.1 provider mappings, and the
 * resolution of a stored value into what it actually establishes.
 *
 * The point of these assertions is that the registry is a CLOSED vocabulary and an HONEST
 * one. Closed: an unregistered value resolves to nothing, and every caller treats that as a
 * refusal -- a registry that minted a profile for an unknown word would leave assuranceLevel
 * free-text with extra ceremony. Honest: what a provider *can* reach and what a particular
 * enrolment *did* reach are different numbers, and the lower one wins.
 */
import {
  AssuranceRegistry,
  identityFromBinding,
  evidenceFromResidence,
} from '../src/core/assurance/registry';
import {
  buildDefaultAssuranceRegistry,
  DEFAULT_ASSURANCE_PROFILES,
  DEFAULT_PROVIDER_MAPPINGS,
  DEFAULT_VALUE_ALIASES,
} from '../src/core/assurance/profiles';

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

function threw(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

function main() {
  console.log('\n== ORCS §8 assurance registry ==\n');
  const registry = buildDefaultAssuranceRegistry();

  console.log('the vocabulary is closed:');
  check(
    'every legacy assurance value resolves to a profile',
    Object.keys(DEFAULT_VALUE_ALIASES).every((v) => registry.resolve(v) !== null),
  );
  check('an unregistered value resolves to nothing', registry.resolve('pretty-sure') === null);
  check('the empty string resolves to nothing', registry.resolve('') === null);
  check(
    'a value that looks like a profile id is still not a value',
    registry.resolve('orcs:profile:high') === null,
  );

  console.log('\nprofiles are governed records (ORCS §8.1):');
  check(
    'every profile carries a version and an issuer',
    DEFAULT_ASSURANCE_PROFILES.every((p) => !!p.version.trim() && !!p.issuer.trim()),
  );
  check(
    'every profile states at least one dimension',
    DEFAULT_ASSURANCE_PROFILES.every((p) => Object.values(p.dimensions).some((d) => d !== undefined)),
  );
  check(
    'every profile records what it does NOT establish',
    DEFAULT_ASSURANCE_PROFILES.every((p) => p.limitations.length > 0),
  );
  check(
    'a profile with no version is refused',
    threw(() =>
      registry.registerProfile({
        id: 'x:ungoverned',
        name: 'Ungoverned',
        version: '',
        issuer: 'somebody',
        dimensions: { identity: 'IAL2' },
        limitations: [],
      }),
    ),
  );
  check(
    'a profile asserting no dimension is refused',
    threw(() =>
      registry.registerProfile({
        id: 'x:empty',
        name: 'Empty',
        version: '1.0',
        issuer: 'somebody',
        dimensions: {},
        limitations: [],
      }),
    ),
  );
  check(
    'a duplicate profile id is refused, never silently replaced',
    threw(() =>
      registry.registerProfile({
        id: 'orcs:profile:verified',
        name: 'Impostor',
        version: '9.9',
        issuer: 'somebody',
        dimensions: { identity: 'IAL3' },
        limitations: [],
      }),
    ),
  );

  console.log('\nprovider mappings (ORCS §8.1):');
  check(
    'every shipped mapping declares version, issuer and verification method',
    DEFAULT_PROVIDER_MAPPINGS.every(
      (m) => !!m.version.trim() && !!m.issuer.trim() && !!m.verificationMethod.trim(),
    ),
  );
  check(
    'every shipped mapping records limitations',
    DEFAULT_PROVIDER_MAPPINGS.every((m) => m.limitations.length > 0),
  );
  check(
    'a mapping naming an unknown profile is refused',
    threw(() =>
      registry.registerMapping({
        providerCode: 'NOWHERE',
        assuranceValue: 'verified',
        profileId: 'orcs:profile:does-not-exist',
        version: '1.0',
        issuer: 'somebody',
        verificationMethod: 'guessing',
        limitations: [],
      }),
    ),
  );
  check(
    'the IMPORT alias resolves as well as DATASET_FILE',
    registry.getMapping('IMPORT', 'basic') !== null &&
      registry.getMapping('DATASET_FILE', 'basic') !== null,
  );

  // The same word means different things from different authorities -- which is why §8.1
  // requires per-provider mappings rather than one global table.
  const mockProfile = registry.resolve('verified', 'MOCK');
  const ninProfile = registry.resolve('verified', 'NG_NIN');
  check(
    'the same value from different providers resolves differently',
    mockProfile?.id === 'orcs:profile:test-only' && ninProfile?.id === 'orcs:profile:verified',
    `MOCK=${mockProfile?.id} NG_NIN=${ninProfile?.id}`,
  );
  check(
    'the MOCK adapter resolves to a profile that disclaims assurance and forbids real use',
    (mockProfile?.limitations ?? []).some((l) => /establishes no/i.test(l)) &&
      (mockProfile?.limitations ?? []).some((l) => /MUST NOT/.test(l)),
  );

  // The bug this section exists for: an imported register declaring `verified` used to
  // resolve to "Verified against an authoritative source" at IAL2, with the §8.1 limitations
  // that source published about itself silently dropped, because the provider-qualified
  // lookup missed and the global alias answered on the word alone.
  console.log('\na mapped provider never falls through to the bare word:');
  check(
    'DATASET_FILE/basic resolves, and carries its §8.1 mapping',
    registry.resolve('basic', 'DATASET_FILE')?.id === 'orcs:profile:basic' &&
      !!registry.getMapping('DATASET_FILE', 'basic'),
  );
  check(
    'DATASET_FILE/verified resolves to NOTHING, rather than borrowing the global profile',
    registry.resolve('verified', 'DATASET_FILE') === null,
  );
  check('the IMPORT alias behaves identically', registry.resolve('verified', 'IMPORT') === null);
  check(
    'an UNMAPPED provider still uses the global alias',
    registry.resolve('verified', 'SOME_UNKNOWN_PROVIDER')?.id === 'orcs:profile:verified',
  );
  check(
    'and the limitations are attached whenever a mapping answers',
    (registry.resolveRecord({
      assuranceLevel: 'basic',
      providerCode: 'DATASET_FILE',
      binding: { method: 'attended_comparison' },
      residence: { assuranceLevel: 'RAL2' },
    })?.limitations ?? []).some((l) => /point-in-time snapshot/i.test(l)),
  );

  console.log('\nderivations reuse the existing vocabularies:');
  check('a bare lookup with no binding is IAL1', identityFromBinding('none') === 'IAL1');
  check('an attended comparison is IAL2', identityFromBinding('attended_comparison') === 'IAL2');
  check(
    'owner authentication at the source is IAL3',
    identityFromBinding('authoritative_authentication') === 'IAL3',
  );
  check('RAL2 residence evidence is EA2', evidenceFromResidence('RAL2') === 'EA2');
  check('RAL3 residence evidence is EA3', evidenceFromResidence('RAL3') === 'EA3');
  check('self-declared residence floors at EA1', evidenceFromResidence('RAL0') === 'EA1');

  console.log('\nresolving a record states what was ACTUALLY established:');
  const bound = registry.resolveRecord({
    assuranceLevel: 'verified',
    providerCode: 'NG_NIN',
    binding: { method: 'attended_comparison' },
    residence: { assuranceLevel: 'RAL2' },
  });
  check('a verified, bound, RAL2 enrolment resolves', bound !== null);
  check('  identity is IAL2', bound?.dimensions.identity === 'IAL2');
  check('  evidence is EA2, from the achieved RAL', bound?.dimensions.evidence === 'EA2');
  check(
    '  the NIMC mapping is attached',
    bound?.mapping?.providerCode === 'NG_NIN' && !!bound?.mapping?.verificationMethod,
  );
  check(
    '  the provider limitation about NIN ownership is carried through',
    (bound?.limitations ?? []).some((l) => /does not prove the applicant owns/i.test(l)),
  );

  // The sharp edge: a provider CAPABLE of IAL3 used without owner binding did not reach it.
  const unbound = registry.resolveRecord({
    assuranceLevel: 'high',
    providerCode: 'IN_AADHAAR',
    binding: { method: 'none' },
    residence: { assuranceLevel: 'RAL1' },
  });
  check('an IAL3-capable provider used with NO binding does not yield IAL3', unbound?.dimensions.identity !== 'IAL3');
  check('  it is capped at IAL1 by the binding actually performed', unbound?.dimensions.identity === 'IAL1');
  check('  while the profile it resolved to still claims IAL3', unbound?.profile.dimensions.identity === 'IAL3');

  console.log('\nidentity and authentication assurance stay separate (ORCS §8):');
  check(
    'a resolved record carries no authentication assurance',
    bound?.dimensions.authentication === undefined,
  );
  check(
    'federation assurance is published as its own profile, not folded into a person',
    registry.getProfile('orcs:profile:federation-sso')?.dimensions.federation === 'FAL2' &&
      registry.getProfile('orcs:profile:federation-sso')?.dimensions.identity === undefined,
  );

  console.log('\nan ungoverned value cannot be resolved into one:');
  check(
    'a record carrying an unregistered value resolves to null, not a default',
    registry.resolveRecord({
      assuranceLevel: 'probably-fine',
      providerCode: 'NG_NIN',
      binding: { method: 'attended_comparison' },
      residence: { assuranceLevel: 'RAL2' },
    }) === null,
  );

  console.log('\nan empty registry is empty (no hidden defaults):');
  const bare = new AssuranceRegistry();
  check('a fresh registry resolves nothing', bare.resolve('verified') === null);
  check('and lists no profiles', bare.listProfiles().length === 0);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main();