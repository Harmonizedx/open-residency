import { createHash, createHmac } from 'node:crypto';

/** Safe dot-path getter: getPath({a:{b:1}}, 'a.b') -> 1 */
export function getPath(obj: unknown, path: string): unknown {
  if (!path) return undefined;
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc == null) return undefined;
    // support array index like items.0.id
    return (acc as Record<string, unknown>)[key];
  }, obj);
}

/**
 * Interpolate {identifiers.nin} / {context.channel} style placeholders in a template
 * against a scope object. Missing keys resolve to empty string.
 */
export function interpolate(
  template: string,
  scope: Record<string, unknown>,
): string {
  return template.replace(/\{([^}]+)\}/g, (_m, expr: string) => {
    const val = getPath(scope, expr.trim());
    return val == null ? '' : String(val);
  });
}

export function interpolateObject(
  tpl: Record<string, string> | undefined,
  scope: Record<string, unknown>,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!tpl) return out;
  for (const [k, v] of Object.entries(tpl)) out[k] = interpolate(v, scope);
  return out;
}

/**
 * Produce a stable, non-reversible subject reference from a raw foundational id.
 * We HMAC with a deployment pepper so that even the residency database never holds
 * the raw national id, and references are not correlatable across deployments.
 *
 * pepper MUST come from a secret (env/KMS) in production.
 */
export function tokenizeSubject(
  providerCode: string,
  rawId: string,
  pepper: string,
): string {
  const mac = createHmac('sha256', pepper)
    .update(`${providerCode}:${rawId}`)
    .digest('hex');
  return `${providerCode.toLowerCase()}:${mac.slice(0, 40)}`;
}

/** Deterministic short hash, handy for status-list indices and correlation ids. */
export function shortHash(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}
