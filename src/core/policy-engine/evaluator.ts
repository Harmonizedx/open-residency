import { Facts, Condition, Rule, PolicyPack, Decision } from './types';

/**
 * The deterministic residency evaluator.
 *
 * Walks each residency class's rule against the supplied facts and returns an explainable
 * decision: which class was approved (the first whose rule is satisfied) or, on rejection,
 * exactly which conditions failed. There is no scoring, no randomness, no hidden state --
 * the same facts and pack always yield the same decision, which is what makes a
 * determination reproducible and appealable.
 *
 * A risk score, when a later phase adds one, may route a case to review; it never appears
 * here, because legal eligibility must be a satisfied rule with a stated basis, not a
 * number that silently invents it.
 */

/** Read a dot-path out of the facts object. */
export function readFact(facts: Facts, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined),
      facts,
    );
}

/** Evaluate one condition. Returns true iff it holds. Unknown facts fail closed (false). */
export function evalCondition(facts: Facts, c: Condition): boolean {
  const actual = readFact(facts, c.path);
  switch (c.op) {
    case 'exists':
      return actual !== undefined && actual !== null;
    case 'eq':
      return actual === c.value;
    case 'neq':
      return actual !== c.value;
    case 'in':
      return Array.isArray(c.value) && c.value.includes(actual);
    case 'gte':
    case 'lte':
    case 'gt':
    case 'lt': {
      // Numeric comparisons only. A non-number on either side fails closed rather than
      // coercing -- a rule that meant to compare numbers must not silently pass on `undefined`.
      const a = actual;
      const b = c.value;
      if (typeof a !== 'number' || typeof b !== 'number') return false;
      return c.op === 'gte' ? a >= b : c.op === 'lte' ? a <= b : c.op === 'gt' ? a > b : a < b;
    }
    default:
      return false;
  }
}

/** The paths referenced by a rule -- used by the floor resolver to enforce forbidden facts. */
export function ruleFactPaths(rule: Rule): string[] {
  return [...(rule.all ?? []), ...(rule.any ?? []), ...(rule.exclusions ?? [])].map((c) => c.path);
}

interface RuleOutcome {
  satisfied: boolean;
  /** Failing conditions, as `<path> <op> <value>`, for explainability. */
  failures: string[];
}

function describe(c: Condition): string {
  return c.op === 'exists' ? `${c.path} exists` : `${c.path} ${c.op} ${JSON.stringify(c.value)}`;
}

/** Evaluate a single rule: all must hold, at least one `any` (if present), no exclusion. */
export function evalRule(facts: Facts, rule: Rule): RuleOutcome {
  const failures: string[] = [];

  for (const c of rule.all ?? []) {
    if (!evalCondition(facts, c)) failures.push(describe(c));
  }

  const anyConds = rule.any ?? [];
  if (anyConds.length > 0 && !anyConds.some((c) => evalCondition(facts, c))) {
    // Report the whole disjunction as the failure: none of the alternatives held.
    failures.push(`any(${anyConds.map(describe).join(' | ')})`);
  }

  for (const c of rule.exclusions ?? []) {
    if (evalCondition(facts, c)) failures.push(`excluded: ${describe(c)}`);
  }

  return { satisfied: failures.length === 0, failures };
}

/**
 * Evaluate the pack against the facts.
 *
 * Classes are tried in declared order; the first satisfied class is the decision. If a
 * `requestedClass` is given, only that class is evaluated (a purpose asking specifically
 * for, say, `student_resident`). On rejection the failed conditions across the tried
 * class(es) are returned so the outcome is explainable.
 */
export function evaluate(pack: PolicyPack, facts: Facts, requestedClass?: string): Decision {
  const version = pack.metadata.version;
  const classIds = requestedClass ? [requestedClass] : Object.keys(pack.rules);
  const failedRules: string[] = [];

  for (const classId of classIds) {
    const rule = pack.rules[classId];
    if (!rule) {
      failedRules.push(`${classId}:UNKNOWN_CLASS`);
      continue;
    }
    const outcome = evalRule(facts, rule);
    if (outcome.satisfied) {
      return {
        decision: 'approved',
        residencyClass: classId,
        satisfiedRules: [rule.id],
        failedRules: [],
        policyVersion: version,
        explanationCode: `APPROVED_${classId.toUpperCase()}`,
      };
    }
    for (const f of outcome.failures) failedRules.push(`${classId}:${f}`);
  }

  return {
    decision: 'rejected',
    satisfiedRules: [],
    failedRules,
    policyVersion: version,
    explanationCode: 'NO_CLASS_SATISFIED',
  };
}
