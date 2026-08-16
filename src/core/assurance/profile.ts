// SPDX-License-Identifier: Apache-2.0

/**
 * The ORCS §8 assurance framework: five dimensions, and the governed profile records that
 * assurance values resolve to.
 *
 * ORCS §8 opens with a prohibition -- "assuranceLevel MUST NOT be a free-text string. Every
 * assurance value must resolve to a governed profile in the Assurance Registry." Before this
 * module, `assuranceLevel` on a resident was one of four words with nothing behind them.
 * `'verified'` was a claim the system made about a person without recording who decided it,
 * by what method, at what version, or what it did not cover -- so a relying party reading it
 * could not tell whether it meant an operator had glanced at a printout or a national
 * authority had authenticated the owner on their own device.
 *
 * Two entities, matching the specification's two halves:
 *
 *   - An `AssuranceProfile` is the canonical record (§8). It states, per dimension, what a
 *     value means; it is versioned and attributed to the authority that governs it.
 *   - A `ProviderAssuranceMapping` is what each identity source publishes about itself
 *     (§8.1): which canonical profile its verification reaches, plus the version, issuer,
 *     verification method and limitations that qualify it.
 *
 * The existing vocabularies are mapped, not replaced. `RAL0..RAL3` (residence evidence) and
 * `BindingMethod` (how the applicant was proven to own the identity) already carry real
 * meaning that the codebase computes carefully; discarding them for a fresh set of enums
 * would lose that and change behaviour. They become the inputs from which the canonical
 * dimensions are derived.
 */

/** How strongly the person's identity was established (ORCS §8). */
export type IdentityAssurance = 'IAL1' | 'IAL2' | 'IAL3';
/** Strength of the current authentication event (ORCS §8). */
export type AuthenticationAssurance = 'AAL1' | 'AAL2' | 'AAL3';
/** Protection of assertions or tokens across systems (ORCS §8). */
export type FederationAssurance = 'FAL1' | 'FAL2' | 'FAL3';
/** Strength and provenance of residency evidence (ORCS §8). */
export type EvidenceAssurance = 'EA1' | 'EA2' | 'EA3';
/** Binding, cryptographic protection and status checking (ORCS §8). */
export type CredentialAssurance = 'CA1' | 'CA2' | 'CA3';

export type AssuranceDimension =
  | 'identity'
  | 'authentication'
  | 'federation'
  | 'evidence'
  | 'credential';

/**
 * The five dimensions of a profile.
 *
 * Every field is optional because a profile is honest about its reach: a mapping published
 * by a national ID registry speaks to identity and says nothing about how a credential is
 * protected, and pretending otherwise is exactly the conflation ORCS §8 separates. A profile
 * with no dimension at all is rejected at registration -- it would assert nothing.
 */
export interface AssuranceDimensions {
  identity?: IdentityAssurance;
  authentication?: AuthenticationAssurance;
  federation?: FederationAssurance;
  evidence?: EvidenceAssurance;
  credential?: CredentialAssurance;
}

/**
 * A governed profile record. This is what an assurance value resolves to.
 *
 * `version` and `issuer` are what make it *governed* rather than merely structured: a
 * profile is somebody's published position, and a relying party that disagrees with it needs
 * to know whose position it is and which revision it read.
 */
export interface AssuranceProfile {
  /** Stable identifier, cited by mappings and by resolved results. */
  id: string;
  /** Human-readable name for operator interfaces and audit output. */
  name: string;
  /** Revision of this profile's definition (ORCS §8.1). */
  version: string;
  /** The authority that governs this profile (ORCS §8.1). */
  issuer: string;
  /** What the profile asserts, per dimension. */
  dimensions: AssuranceDimensions;
  /** What this profile does NOT establish. Never empty in practice; see the baseline set. */
  limitations: string[];
}

/**
 * What one identity source publishes about its own verification (ORCS §8.1).
 *
 * "Each national ID, municipal register, field-verification process or sectoral identity
 * provider MUST publish a mapping to the canonical profile, including version, issuer,
 * verification method and limitations."
 */
export interface ProviderAssuranceMapping {
  /** Foundational provider code, as used by the provider registry (NG_NIN, MOSIP_IDA, ...). */
  providerCode: string;
  /** The declared value this provider yields on success ('verified', 'high', ...). */
  assuranceValue: string;
  /** The canonical profile that value resolves to. */
  profileId: string;
  /** Revision of this mapping (ORCS §8.1). */
  version: string;
  /** Who publishes the mapping -- the identity source or the authority operating it (§8.1). */
  issuer: string;
  /** How the verification is actually performed (ORCS §8.1). */
  verificationMethod: string;
  /** What this verification does not establish (ORCS §8.1). */
  limitations: string[];
}

/**
 * The result of resolving a resident's recorded assurance.
 *
 * `authentication` is deliberately absent from this type. Authentication assurance describes
 * a *sign-in event*, not a person: it is produced per session by `core/sso/assurance.ts` and
 * carried in the id_token's `acr`. Folding it in here would recreate the conflation ORCS §8
 * separates, and would let a record assert a strength that was true at some past login.
 */
export interface ResolvedAssurance {
  /** The profile the recorded value resolved to. */
  profile: AssuranceProfile;
  /** The §8.1 mapping for the provider that performed the verification, when known. */
  mapping?: ProviderAssuranceMapping;
  /**
   * The dimensions as they apply to THIS resident, after the record's own signals are
   * folded in -- binding method raising or lowering identity, achieved RAL setting evidence.
   * The profile states what the provider can reach; this states what was reached here.
   */
  dimensions: AssuranceDimensions;
  /** Profile limitations plus any added by the provider mapping, de-duplicated. */
  limitations: string[];
}