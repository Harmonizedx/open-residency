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

function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function escapeText(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export interface XmlParseOptions {
  /** Drop namespace prefixes so `ns2:Body` maps as `Body`. Default true. */
  stripNamespaces?: boolean;
}

/**
 * A small, dependency-free XML/SOAP parser sufficient for national-ID verification
 * responses: elements, nesting, text, attributes (as `@_name`), and repeated elements
 * (folded into arrays). A leaf element with only text collapses to that string, so a
 * response mapping can address `Body.VerifyResponse.person.firstName` the same dot-path
 * way it addresses JSON. Namespace prefixes are stripped by default.
 *
 * Deliberately NOT a full XML implementation: no DTD/entity expansion beyond the five
 * predefined entities + numeric refs, no processing instructions, no `>` inside attribute
 * values, no mixed text+element content preserved in order. Government SOAP responses fit
 * inside these limits; anything that does not should use a dedicated adapter.
 */
export function parseXml(
  xml: string,
  opts: XmlParseOptions = {},
): Record<string, unknown> {
  const stripNs = opts.stripNamespaces !== false;
  const norm = (name: string): string => (stripNs ? name.replace(/^[^:]*:/, '') : name);

  // CDATA can contain <, >, & -- escape its payload to entities so the tag scanner
  // below never sees stray markup, then decodeEntities restores it as text.
  const cleaned = xml
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_m, c: string) => escapeText(c))
    .replace(/<\?[\s\S]*?\?>/g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!DOCTYPE[^>]*>/gi, '');

  interface Node {
    children: Record<string, unknown>;
    text: string;
  }
  const root: Node = { children: {}, text: '' };
  const stack: Node[] = [root];

  const addChild = (obj: Record<string, unknown>, key: string, value: unknown): void => {
    if (key in obj) {
      const existing = obj[key];
      if (Array.isArray(existing)) existing.push(value);
      else obj[key] = [existing, value];
    } else {
      obj[key] = value;
    }
  };

  const finalize = (node: Node): unknown => {
    const keys = Object.keys(node.children);
    const text = node.text.trim();
    if (keys.length === 0) return decodeEntities(text);
    if (text) node.children['#text'] = decodeEntities(text);
    return node.children;
  };

  const parseAttrs = (attrStr: string): Record<string, string> => {
    const out: Record<string, string> = {};
    const re = /([\w.:-]+)\s*=\s*"([^"]*)"|([\w.:-]+)\s*=\s*'([^']*)'/g;
    let a: RegExpExecArray | null;
    while ((a = re.exec(attrStr))) {
      const name = norm(a[1] ?? a[3]);
      out['@_' + name] = decodeEntities(a[2] ?? a[4] ?? '');
    }
    return out;
  };

  const tagRe = /<(\/?)([A-Za-z_][\w.:-]*)((?:\s[^<>]*?)?)(\/?)>|([^<]+)/g;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(cleaned))) {
    const [, closing, rawName, attrStr, selfClose, textChunk] = m;
    if (textChunk != null) {
      stack[stack.length - 1].text += textChunk;
      continue;
    }
    const name = norm(rawName);
    if (closing) {
      const node = stack.pop();
      if (!node || stack.length === 0) continue; // unbalanced close: ignore
      addChild(stack[stack.length - 1].children, name, finalize(node));
    } else {
      const node: Node = { children: {}, text: '' };
      for (const [k, v] of Object.entries(parseAttrs(attrStr))) node.children[k] = v;
      if (selfClose) {
        addChild(stack[stack.length - 1].children, name, finalize(node));
      } else {
        stack.push(node);
      }
    }
  }
  return finalize(root) as Record<string, unknown>;
}

/**
 * Minimal RFC-4180-ish CSV parser: a header row names the columns, and every subsequent
 * row becomes a `{ column: value }` record. Handles quoted fields, embedded commas and
 * newlines, and `""` escapes. Enough to ingest a register extract; not a full CSV engine.
 */
export function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  const src = text.replace(/\r\n?/g, '\n');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  const nonEmpty = rows.filter((r) => r.some((v) => v.trim() !== ''));
  if (nonEmpty.length === 0) return [];
  const header = nonEmpty[0].map((h) => h.trim());
  return nonEmpty.slice(1).map((r) => {
    const rec: Record<string, string> = {};
    header.forEach((h, idx) => (rec[h] = (r[idx] ?? '').trim()));
    return rec;
  });
}
