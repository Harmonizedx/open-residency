import { PolicyPack, RightsFloor } from './types';
import { ruleFactPaths } from './evaluator';

/**
 * The sealed human-rights floor and the layered-merge resolver.
 *
 * This is the security-critical heart of the engine. The rights guarantee -- "no
 * jurisdiction can, through configuration, disable a mandatory right, privacy, or security
 * control" -- is only real if the resolver REJECTS a violating override at merge time
 * rather than silently dropping it. A silently-dropped override reads to an authority as
 * "accepted", and the discriminatory rule they wrote appears to be in force. So every
 * violation here throws, loudly, and (in the platform) refuses to boot the pack.
 *
 * Two enforcements, together forming the floor:
 *
 *   SEALED FIELDS. Config keys the floor marks sealed; no layer's `overrides` may touch one.
 *   This covers, e.g., `privacy.national_identifier.expose_in_credential` (forced false --
 *   the national ID never enters a credential).
 *
 *   FORBIDDEN FACT PATHS. Per residency class, fact paths a rule for that class may NOT
 *   reference. This is the concrete, enforceable form of "origin/ancestry must not affect
 *   ordinary residency": the floor forbids `ordinary_resident` rules from referencing any
 *   origin/ancestry fact (`applicant.origin`, `applicant.indigene`, ...), so a pack that
 *   tries to reject non-indigenes from ordinary residency is rejected at merge -- it cannot
 *   be expressed. This is the indigene/settler guard that has caused real exclusion, made
 *   structurally impossible rather than merely discouraged.
 */

export class FloorViolationError extends Error {
  constructor(
    message: string,
    readonly kind: 'SEALED_FIELD' | 'FORBIDDEN_FACT_PATH',
    readonly detail: string,
  ) {
    super(message);
    this.name = 'FloorViolationError';
  }
}

/** Does a forbidden path match a referenced path? Prefix match, so forbidding
 *  `applicant.origin` also forbids `applicant.origin.state`. */
function pathMatches(forbidden: string, referenced: string): boolean {
  return referenced === forbidden || referenced.startsWith(`${forbidden}.`);
}

/**
 * Check one pack's rules against a floor's forbidden fact paths. Throws on the first
 * violation. Exposed so the conformance runner can assert a pack is floor-clean
 * independently of a full merge.
 */
export function enforceForbiddenPaths(pack: PolicyPack, floor: RightsFloor): void {
  const forbidden = floor.forbiddenFactPaths ?? {};
  for (const [classId, paths] of Object.entries(forbidden)) {
    const rule = pack.rules[classId];
    if (!rule) continue;
    const referenced = ruleFactPaths(rule);
    for (const f of paths) {
      const hit = referenced.find((r) => pathMatches(f, r));
      if (hit) {
        throw new FloorViolationError(
          `pack "${pack.metadata.name}@${pack.metadata.version}" rule for "${classId}" references ` +
            `"${hit}", which the human-rights floor forbids for that class (origin/ancestry must ` +
            `not affect ${classId}). This override is rejected, not dropped.`,
          'FORBIDDEN_FACT_PATH',
          `${classId}:${hit}`,
        );
      }
    }
  }
}

/** Check a layer's overrides against the sealed field list. Throws on the first sealed touch. */
export function enforceSealedFields(overrides: Record<string, unknown> | undefined, floor: RightsFloor): void {
  const sealed = new Set(floor.sealedFields ?? []);
  for (const key of Object.keys(overrides ?? {})) {
    if (sealed.has(key)) {
      throw new FloorViolationError(
        `override of sealed field "${key}" is rejected: it is part of the human-rights/privacy ` +
          `floor and cannot be weakened by a lower pack.`,
        'SEALED_FIELD',
        key,
      );
    }
  }
}

/**
 * Merge a base (floor-bearing) pack with ordered layers, enforcing the floor at each step.
 *
 * Precedence: later layers override earlier ones for non-sealed config. The floor is taken
 * from the base and inherited by the result; layers cannot alter it. Any sealed-field
 * override, or any rule referencing a forbidden fact path, throws -- the merge fails closed.
 */
export function mergePacks(base: PolicyPack, ...layers: PolicyPack[]): PolicyPack {
  const floor: RightsFloor = base.floor ?? {};

  // The base itself must be floor-clean (it defines the classes the floor protects).
  enforceForbiddenPaths(base, floor);

  const merged: PolicyPack = {
    metadata: base.metadata,
    rules: { ...base.rules },
    floor,
    config: { ...(base.config ?? {}) },
  };

  for (const layer of layers) {
    enforceSealedFields(layer.overrides, floor);
    enforceForbiddenPaths(layer, floor);

    // Rules: a layer may add or replace classes it defines (its own rules are floor-checked
    // above). Sealed fields are never in `rules`, so rule replacement is safe.
    merged.rules = { ...merged.rules, ...layer.rules };
    // Config/overrides: non-sealed keys win by layer order.
    merged.config = { ...merged.config, ...(layer.config ?? {}), ...(layer.overrides ?? {}) };
    // Carry the most recent metadata version so a decision pins the effective policy version.
    merged.metadata = { ...merged.metadata, version: layer.metadata.version };
  }

  return merged;
}
