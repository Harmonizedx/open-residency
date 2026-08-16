// SPDX-License-Identifier: Apache-2.0

import { BindingMethod } from '../proofing/binding';
import { ResidenceAssuranceLevel } from '../proofing/residence';
import {
  AssuranceDimensions,
  AssuranceProfile,
  EvidenceAssurance,
  IdentityAssurance,
  ProviderAssuranceMapping,
  ResolvedAssurance,
} from './profile';

/**
 * The Assurance Registry (ORCS §8).
 *
 * Its whole purpose is to be a CLOSED vocabulary. `resolve` returns null for anything not
 * registered, and every caller treats null as a refusal rather than a default -- that is what
 * "MUST NOT be a free-text string" means operationally. A registry that invented a profile
 * for an unrecognised word would leave the string free-text with extra steps.
 */
export class AssuranceRegistry {
  private profiles = new Map<string, AssuranceProfile>();
  /** Keyed by `${providerCode}:${assuranceValue}` -- a provider may map each value it emits. */
  private mappings = new Map<string, ProviderAssuranceMapping>();
  /** Declared assurance value -> profile id, for values not qualified by a provider. */
  private valueAliases = new Map<string, string>();
  /** Providers that have published at least one §8.1 mapping. See `resolve`. */
  private providersWithMappings = new Set<string>();

  constructor(profiles: AssuranceProfile[] = [], mappings: ProviderAssuranceMapping[] = []) {
    for (const p of profiles) this.registerProfile(p);
    for (const m of mappings) this.registerMapping(m);
  }

  /**
   * Add a profile.
   *
   * Rejects a duplicate id, because a silently replaced profile would change the meaning of
   * every value already resolved against it. Rejects a profile asserting no dimension, and
   * one missing version or issuer -- an unattributed, unversioned profile is not governed,
   * and admitting it would satisfy the letter of §8 while losing its point.
   */
  registerProfile(profile: AssuranceProfile): void {
    if (this.profiles.has(profile.id)) {
      throw new Error(`Assurance profile "${profile.id}" is already registered`);
    }
    if (!profile.version?.trim() || !profile.issuer?.trim()) {
      throw new Error(
        `Assurance profile "${profile.id}" must declare both a version and an issuer ` +
          '(ORCS §8.1); an unattributed profile is not a governed record.',
      );
    }
    if (Object.values(profile.dimensions).every((v) => v === undefined)) {
      throw new Error(
        `Assurance profile "${profile.id}" asserts no dimension, so it cannot be what an ` +
          'assurance value means.',
      );
    }
    this.profiles.set(profile.id, profile);
  }

  /** Register a §8.1 provider mapping. The profile it names must already exist. */
  registerMapping(mapping: ProviderAssuranceMapping): void {
    if (!this.profiles.has(mapping.profileId)) {
      throw new Error(
        `Provider mapping ${mapping.providerCode}/${mapping.assuranceValue} names unknown ` +
          `profile "${mapping.profileId}"`,
      );
    }
    if (!mapping.version?.trim() || !mapping.issuer?.trim() || !mapping.verificationMethod?.trim()) {
      throw new Error(
        `Provider mapping ${mapping.providerCode}/${mapping.assuranceValue} must declare ` +
          'version, issuer and verificationMethod (ORCS §8.1).',
      );
    }
    this.mappings.set(`${mapping.providerCode}:${mapping.assuranceValue}`, mapping);
    this.providersWithMappings.add(mapping.providerCode);
  }

  /** Alias a declared assurance value to a canonical profile. */
  registerValue(value: string, profileId: string): void {
    if (!this.profiles.has(profileId)) {
      throw new Error(`Assurance value "${value}" names unknown profile "${profileId}"`);
    }
    this.valueAliases.set(value, profileId);
  }

  getProfile(id: string): AssuranceProfile | null {
    return this.profiles.get(id) ?? null;
  }

  listProfiles(): AssuranceProfile[] {
    return [...this.profiles.values()];
  }

  listMappings(): ProviderAssuranceMapping[] {
    return [...this.mappings.values()];
  }

  /**
   * Resolve an assurance value to its governed profile.
   *
   * A provider-qualified lookup wins when one exists: the same word can mean different
   * things from different authorities, which is the reason §8.1 requires per-provider
   * mappings at all rather than a single global table.
   */
  resolve(value: string, providerCode?: string): AssuranceProfile | null {
    if (providerCode) {
      const mapped = this.mappings.get(`${providerCode}:${value}`);
      if (mapped) return this.profiles.get(mapped.profileId) ?? null;
      // A provider that has published ANY mapping does not fall through to the global alias.
      //
      // Falling through looks harmless and is not. The alias resolves on the word alone, so an
      // imported register declaring `verified` resolved to "Verified against an authoritative
      // source" at IAL2 -- and the §8.1 limitations that authority published about itself, the
      // ones saying a file import has no liveness and no owner authentication, were silently
      // dropped because the qualified lookup missed. That is fail-open: the deployment gets a
      // better answer than it earned, and the caveats that made the answer honest disappear.
      //
      // So an unmapped value from a mapped provider resolves to NOTHING, and the deployment
      // has to publish what that value means for that source. Which is what §8.1 asks of it.
      if (this.providersWithMappings.has(providerCode)) return null;
    }
    const aliased = this.valueAliases.get(value);
    return aliased ? (this.profiles.get(aliased) ?? null) : null;
  }

  getMapping(providerCode: string, value: string): ProviderAssuranceMapping | null {
    return this.mappings.get(`${providerCode}:${value}`) ?? null;
  }

  /**
   * Resolve everything a resident record establishes.
   *
   * The profile says what this provider's verification can reach. The record says what was
   * actually reached for this person -- the binding method performed at the desk, the
   * residence evidence achieved. Identity is the LOWER of the two: a provider capable of
   * IAL3 that was used without owner binding did not establish IAL3 for this applicant.
   * Overstating it here would be the fail-open default all over again, one layer up.
   *
   * Returns null when the value does not resolve, so a caller cannot proceed on an
   * ungoverned string.
   */
  resolveRecord(record: {
    assuranceLevel: string;
    providerCode: string;
    binding: { method: BindingMethod };
    residence: { assuranceLevel: ResidenceAssuranceLevel };
  }): ResolvedAssurance | null {
    const profile = this.resolve(record.assuranceLevel, record.providerCode);
    if (!profile) return null;

    const mapping = this.getMapping(record.providerCode, record.assuranceLevel) ?? undefined;

    const fromBinding = identityFromBinding(record.binding.method);
    const dimensions: AssuranceDimensions = {
      ...profile.dimensions,
      // Identity is capped by what the binding actually proved.
      identity: profile.dimensions.identity
        ? lowerIdentity(profile.dimensions.identity, fromBinding)
        : fromBinding,
      // Evidence is a property of THIS enrolment, not of the provider.
      evidence: evidenceFromResidence(record.residence.assuranceLevel),
      // Authentication is per session; a record never carries one. See ResolvedAssurance.
      authentication: undefined,
    };

    const limitations = [...new Set([...profile.limitations, ...(mapping?.limitations ?? [])])];
    return { profile, mapping, dimensions, limitations };
  }
}

const IDENTITY_RANK: Record<IdentityAssurance, number> = { IAL1: 1, IAL2: 2, IAL3: 3 };

function lowerIdentity(a: IdentityAssurance, b: IdentityAssurance): IdentityAssurance {
  return IDENTITY_RANK[a] <= IDENTITY_RANK[b] ? a : b;
}

/**
 * Binding method -> identity assurance.
 *
 * The mapping follows the existing BINDING_RANK ordering rather than inventing a second
 * opinion about which method is stronger. A bare lookup is IAL1 however authoritative the
 * registry is: anyone who knows the number passes it, which establishes that the identity
 * exists, not that this applicant owns it.
 */
export function identityFromBinding(method: BindingMethod): IdentityAssurance {
  switch (method) {
    case 'authoritative_authentication':
      return 'IAL3';
    case 'face_match':
    case 'fingerprint_match':
      return 'IAL2';
    case 'attended_comparison':
      return 'IAL2';
    case 'none':
    default:
      return 'IAL1';
  }
}

/**
 * Residence assurance level -> evidence assurance.
 *
 * RAL0 is self-declaration, which is evidence of intent rather than of residence; it floors
 * at EA1 because ORCS defines no EA0, and the limitation is carried in the profile text.
 */
export function evidenceFromResidence(ral: ResidenceAssuranceLevel): EvidenceAssurance {
  switch (ral) {
    case 'RAL3':
      return 'EA3';
    case 'RAL2':
      return 'EA2';
    case 'RAL1':
    case 'RAL0':
    default:
      return 'EA1';
  }
}
