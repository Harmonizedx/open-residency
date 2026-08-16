// SPDX-License-Identifier: Apache-2.0

import { AssuranceProfile, ProviderAssuranceMapping } from './profile';
import { AssuranceRegistry } from './registry';

/**
 * The baseline governed profiles and the §8.1 mappings each shipped provider publishes.
 *
 * This is a starting position, not a finished one, and it says so in each entry. A real
 * deployment replaces the mapping for its own identity source with the one its operator
 * publishes -- that is the whole point of §8.1, and a mapping this repository invented on an
 * authority's behalf would be a guess wearing a version number. What ships here is what can
 * be said truthfully from the adapter's own behaviour: a registry lookup proves a record
 * exists, an authenticated flow proves the owner responded, an imported file proves neither.
 *
 * The four legacy values -- none / basic / verified / high -- are aliased to profiles rather
 * than removed. ORRA §15 asks for additive migration, and the enum is load-bearing across
 * config validation, the residency service and the issued credential; making every value
 * resolve is what ORCS §8 requires, and does not require deleting the vocabulary that got
 * here first.
 */

const ISSUER = 'OpenResidency Assurance Authority (deployment default)';
const VERSION = '1.0';

/**
 * The credential dimension is the same for every profile below, because it is a property of
 * this system rather than of the identity source: every residency credential is Ed25519
 * signed and carries a Bitstring Status List reference, so it is cryptographically protected
 * and status-checkable. Holder binding is where the formats differ, which is why CA3 is not
 * claimed -- see the limitation carried on each profile.
 */
const CREDENTIAL_LIMITATION =
  'Credential assurance covers signing and status checking. Holder-key binding is present ' +
  'on the OpenID4VCI path and absent on the offline QR credential, so CA3 is not asserted ' +
  'uniformly.';

export const DEFAULT_ASSURANCE_PROFILES: AssuranceProfile[] = [
  {
    id: 'orcs:profile:unverified',
    name: 'Unverified',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { identity: 'IAL1', credential: 'CA2' },
    limitations: [
      'The identity source confirmed nothing about this person. Not sufficient for residency issuance on its own.',
      CREDENTIAL_LIMITATION,
    ],
  },
  {
    id: 'orcs:profile:basic',
    name: 'Basic identity check',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { identity: 'IAL1', credential: 'CA2' },
    limitations: [
      'Establishes that a matching record exists in the source, not that the applicant owns it.',
      CREDENTIAL_LIMITATION,
    ],
  },
  {
    id: 'orcs:profile:verified',
    name: 'Verified against an authoritative source',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { identity: 'IAL2', credential: 'CA2' },
    limitations: [
      'IAL2 is reached only when the applicant was also bound to the record; a lookup alone caps at IAL1.',
      CREDENTIAL_LIMITATION,
    ],
  },
  {
    id: 'orcs:profile:high',
    name: 'Owner authenticated at the source',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { identity: 'IAL3', credential: 'CA2' },
    limitations: [
      'The source authenticated the owner. Reaching IAL3 here still requires that binding to have been performed at enrolment.',
      CREDENTIAL_LIMITATION,
    ],
  },
  {
    id: 'orcs:profile:test-only',
    name: 'Test provider — establishes nothing',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { identity: 'IAL1', credential: 'CA2' },
    limitations: [
      'MOCK is a development adapter that returns a fixed answer. It establishes no identity assurance whatsoever and MUST NOT serve real residents.',
      CREDENTIAL_LIMITATION,
    ],
  },
  /**
   * Federation assurance describes the SSO layer, not a person, so nothing on a resident
   * record resolves to it. It is published so a relying party integrating with the IdP can
   * cite a governed record for what the assertion protection is.
   */
  {
    id: 'orcs:profile:federation-sso',
    name: 'Residency IdP assertion protection',
    version: VERSION,
    issuer: ISSUER,
    dimensions: { federation: 'FAL2' },
    limitations: [
      'FAL2 reflects signed assertions with pairwise subject identifiers over OIDC Authorization Code + PKCE. Assertions are signed, not encrypted, so FAL3 is not asserted.',
    ],
  },
];

/** ORCS §8.1 mappings for the adapters this repository ships. */
export const DEFAULT_PROVIDER_MAPPINGS: ProviderAssuranceMapping[] = [
  {
    providerCode: 'NG_NIN',
    assuranceValue: 'verified',
    profileId: 'orcs:profile:verified',
    version: VERSION,
    issuer: 'National Identity Management Commission (NIMC), Nigeria — mapping published by the deployment pending NIMC’s own',
    verificationMethod:
      'Demographic lookup against the National Identity Database via a licensed verification gateway, with attended comparison at the enrolment desk.',
    limitations: [
      'A NIN match alone does not prove the applicant owns the identity: anyone holding the number passes it. Owner binding comes from the enrolment desk, not from NIMC.',
      'Residence carried in the NIN record is self-declared to NIMC and resolves only to state level, so it cannot establish ward residence.',
    ],
  },
  {
    providerCode: 'IN_AADHAAR',
    assuranceValue: 'high',
    profileId: 'orcs:profile:high',
    version: VERSION,
    issuer: 'Unique Identification Authority of India (UIDAI) — mapping published by the deployment pending UIDAI’s own',
    verificationMethod:
      'Aadhaar OTP authentication delivered to the mobile number registered against the Aadhaar number.',
    limitations: [
      'Establishes control of the registered mobile number at the moment of authentication, not the physical presence of the holder.',
      'Says nothing about residence in the issuing jurisdiction.',
    ],
  },
  {
    providerCode: 'MOSIP_IDA',
    assuranceValue: 'high',
    profileId: 'orcs:profile:high',
    version: VERSION,
    issuer: 'MOSIP IDA deployment operator — mapping published by the operator of the connected IDA instance',
    verificationMethod:
      'MOSIP Identity Authentication encrypted request envelope (OTP, demographic or biometric authentication, per deployment configuration).',
    limitations: [
      'What is established depends on which IDA authentication type the deployment enables; a demographic-only configuration does not authenticate the owner.',
      'eKYC attribute release is off by default, so a success attests authentication rather than identity attributes.',
    ],
  },
  {
    providerCode: 'GENERIC_REST',
    assuranceValue: 'verified',
    profileId: 'orcs:profile:verified',
    version: VERSION,
    issuer: 'Deployment-configured registry operator',
    verificationMethod: 'REST verification call declared in the country configuration.',
    limitations: [
      'This is a transport, not an authority. The mapping is only as strong as the registry configured behind it, and a deployment MUST replace this entry with the operator’s published mapping.',
    ],
  },
  {
    providerCode: 'GENERIC_XML',
    assuranceValue: 'verified',
    profileId: 'orcs:profile:verified',
    version: VERSION,
    issuer: 'Deployment-configured registry operator',
    verificationMethod: 'SOAP/XML verification call declared in the country configuration.',
    limitations: [
      'This is a transport, not an authority. The mapping is only as strong as the registry configured behind it, and a deployment MUST replace this entry with the operator’s published mapping.',
    ],
  },
  {
    providerCode: 'DATASET_FILE',
    assuranceValue: 'basic',
    profileId: 'orcs:profile:basic',
    version: VERSION,
    issuer: 'Deployment operator (imported register)',
    verificationMethod:
      'Exact match on a configured key against an imported register file, with demographic cross-check.',
    limitations: [
      'A file import is a point-in-time snapshot: it has no liveness, no owner authentication, and no way to observe a change made in the source after export.',
      'Provenance is only as good as the exporting register and the integrity of the transfer.',
    ],
  },
  {
    providerCode: 'MOCK',
    assuranceValue: 'verified',
    profileId: 'orcs:profile:test-only',
    version: VERSION,
    issuer: 'OpenResidency (development adapter)',
    verificationMethod: 'None. Returns a fixed response for local development and tests.',
    limitations: [
      'Establishes nothing. Present so that a demo deployment still resolves to a governed record rather than an ungoverned string, and so that the record says plainly that it is a test.',
    ],
  },
];

/**
 * `IMPORT` is a configuration alias for `DATASET_FILE`. The mapping is duplicated under both
 * codes because a record stores whichever code the config declared, and a resolution that
 * depended on knowing the alias table would fail for exactly the deployments using the alias.
 */
const IMPORT_ALIAS: ProviderAssuranceMapping = {
  ...DEFAULT_PROVIDER_MAPPINGS.find((m) => m.providerCode === 'DATASET_FILE')!,
  providerCode: 'IMPORT',
};

/** Legacy declared values, aliased to canonical profiles for provider-less resolution. */
export const DEFAULT_VALUE_ALIASES: Record<string, string> = {
  none: 'orcs:profile:unverified',
  basic: 'orcs:profile:basic',
  verified: 'orcs:profile:verified',
  high: 'orcs:profile:high',
};

/** The registry a deployment starts from. */
export function buildDefaultAssuranceRegistry(): AssuranceRegistry {
  const registry = new AssuranceRegistry(DEFAULT_ASSURANCE_PROFILES, [
    ...DEFAULT_PROVIDER_MAPPINGS,
    IMPORT_ALIAS,
  ]);
  for (const [value, profileId] of Object.entries(DEFAULT_VALUE_ALIASES)) {
    registry.registerValue(value, profileId);
  }
  return registry;
}