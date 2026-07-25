/**
 * Residency policy engine — core types.
 *
 * The engine reasons over ABSTRACT primitives only. No country, subnational unit, document
 * type, legal instrument, or threshold appears here or anywhere in `src/core` -- those live
 * in signed policy packs loaded at runtime (see docs/RESIDENCY-POLICY.md). The "bug test":
 * if a rule names a jurisdiction, it belongs in a pack, not in this module.
 *
 * A decision is declarative data evaluated by a small deterministic evaluator that emits
 * `satisfiedRules`/`failedRules`. Explainability is a property of the structure, not a
 * feature bolted on: because rules are plain data walked step by step, every determination
 * can say exactly which rules fired and why. That is why the foundation is a purpose-built
 * evaluator rather than a delegation to an opaque policy language.
 */

/** Abstract facts a rule reasons over. Deliberately open: packs and callers agree on paths
 *  like `identity.assuranceRank`, `evidence.authoritative.count`, `applicant.age`. The
 *  engine never hard-codes a domain meaning for any path. */
export type Facts = Record<string, unknown>;

/** A single comparison against a fact at `path`. */
export interface Condition {
  path: string;
  op: 'gte' | 'lte' | 'gt' | 'lt' | 'eq' | 'neq' | 'in' | 'exists';
  /** Right-hand operand. Omitted for `exists`. For `in`, an array. */
  value?: unknown;
}

/**
 * A rule for one residency class. Satisfied when EVERY `all` condition holds, AT LEAST ONE
 * `any` condition holds (or `any` is empty), and NO `exclusion` holds. `any` is where
 * inclusive alternative evidence pathways live -- a person may qualify by an authoritative
 * record OR by attestation + physical verification, so no single document is mandatory.
 */
export interface Rule {
  id: string;
  all?: Condition[];
  any?: Condition[];
  exclusions?: Condition[];
}

/** Pack metadata. Governance fields are validated/enforced in a later phase; carried now so
 *  the shape is stable. */
export interface PackMetadata {
  name: string;
  version: string;
  owner?: string;
  effectiveFrom?: string;
  expiresAt?: string;
}

/**
 * The rights floor a lower pack may not weaken.
 *
 * `sealedFields` are config keys no override may touch. `forbiddenFactPaths` names, per
 * residency class, fact paths a rule for that class may NOT reference -- this is the
 * concrete, enforceable form of "origin/ancestry must not affect ordinary residency": the
 * floor forbids `ordinary_resident` rules from referencing any origin/ancestry fact, and
 * the resolver rejects a pack that does.
 */
export interface RightsFloor {
  sealedFields?: string[];
  forbiddenFactPaths?: Record<string, string[]>;
}

/** A policy pack: metadata, residency-class rules, optional floor, and layering directives. */
export interface PolicyPack {
  metadata: PackMetadata;
  /** classId -> rule. Evaluated in insertion order; the first satisfied class is the decision. */
  rules: Record<string, Rule>;
  /** Only the global baseline sets this; lower packs inherit and cannot weaken it. */
  floor?: RightsFloor;
  /** Config key/value overrides a layer applies to the one above it. */
  overrides?: Record<string, unknown>;
  /** Arbitrary declared config (validity days, etc.); merged with override precedence. */
  config?: Record<string, unknown>;
}

export interface Decision {
  decision: 'approved' | 'rejected';
  residencyClass?: string;
  /** Rule ids that were satisfied (approved: the one class rule; rejected: []). */
  satisfiedRules: string[];
  /** For a rejection, the conditions that failed, as `<classId>:<path> <op> <value>`. */
  failedRules: string[];
  policyVersion: string;
  /** A short, stable code for the outcome, for UIs and appeals. */
  explanationCode: string;
}
