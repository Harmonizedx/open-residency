import { createHash, randomBytes } from 'node:crypto';

/**
 * Human-facing Residency ID.
 *
 * The default is `<UNIT>-<block>-<block>-<checkDigit>` (e.g. `KT-7F3A-9K2P-4`): Crockford
 * base32 (no I/L/O/U) so it reads aloud, dictates over a phone line, and prints cleanly,
 * with a trailing check character that catches transcription errors when an operator keys
 * it in.
 *
 * But a jurisdiction may have a statutory or legacy numbering scheme -- e.g. a purely
 * numeric 12-digit ID -- so the format is a configurable ruleset (`IdFormat`). Omitting
 * the config reproduces the default above byte-for-byte, and, crucially, IDs already
 * issued under the default keep validating, because the default's check computation is
 * unchanged.
 *
 * A deliberate non-feature: there is no free-form template that could interpolate a
 * submitted value. The random body is the only variable part, so the foundational number
 * (NIN/Aadhaar/...) can never be embedded in a public, shareable identifier. "Linked to
 * the NIN" is the registry's tokenized subjectRef, never something encoded in the ID.
 */

const ALPHABETS = {
  // Crockford base32: no I, L, O, U -- unambiguous when spoken or hand-written.
  crockford32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
  numeric: '0123456789',
  alphanumeric: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  hex: '0123456789ABCDEF',
} as const;

export type IdAlphabet = keyof typeof ALPHABETS;
export type ChecksumAlgorithm = 'crockford-sha256' | 'luhn' | 'mod97-10' | 'none';
export type PrefixMode = 'unit' | 'static' | 'country' | 'none';

export interface IdFormat {
  /** Character set for the random body. */
  alphabet: IdAlphabet;
  /** Overrides `alphabet` with an explicit character set when set. */
  customAlphabet?: string;
  /** Segment lengths of the random body, e.g. [4,4] -> XXXX-XXXX, [12] -> XXXXXXXXXXXX. */
  groups: number[];
  /** Joins the prefix, body segments, and check segment. May be empty. */
  separator: string;
  case: 'upper' | 'lower';
  prefix: { mode: PrefixMode; value?: string };
  checkDigit: { enabled: boolean; algorithm: ChecksumAlgorithm };
}

/** The default format: identical output and validation to the original hardcoded scheme. */
export const DEFAULT_ID_FORMAT: IdFormat = {
  alphabet: 'crockford32',
  groups: [4, 4],
  separator: '-',
  case: 'upper',
  prefix: { mode: 'unit' },
  checkDigit: { enabled: true, algorithm: 'crockford-sha256' },
};

function alphabetOf(format: IdFormat): string {
  return format.customAlphabet && format.customAlphabet.length >= 2
    ? format.customAlphabet
    : ALPHABETS[format.alphabet];
}

function applyCase(s: string, c: 'upper' | 'lower'): string {
  return c === 'lower' ? s.toLowerCase() : s.toUpperCase();
}

function prefixOf(format: IdFormat, unitCode: string, countryCode?: string): string {
  switch (format.prefix.mode) {
    case 'unit':
      return unitCode;
    case 'country':
      return countryCode ?? '';
    case 'static':
      return format.prefix.value ?? '';
    case 'none':
    default:
      return '';
  }
}

// ---- Checksums ------------------------------------------------------------------------

/** The original check: one Crockford char from the first byte of sha256(core). Preserved. */
function crockfordSha256(core: string): string {
  const sum = createHash('sha256').update(core).digest()[0];
  return ALPHABETS.crockford32[sum % 32];
}

/** Luhn check digit over a numeric string. Single digit; catches most keying errors. */
function luhn(body: string): string {
  let sum = 0;
  let double = true; // the digit to the left of the (appended) check is doubled
  for (let i = body.length - 1; i >= 0; i--) {
    let d = body.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return String((10 - (sum % 10)) % 10);
}

/** ISO 7064 MOD 97-10: two check digits, strong transposition detection. */
function mod97_10(body: string): string {
  let rem = 0;
  for (const ch of body + '00') rem = (rem * 10 + (ch.charCodeAt(0) - 48)) % 97;
  const check = (98 - rem) % 97;
  return check.toString().padStart(2, '0');
}

/** Number of characters a checksum algorithm produces. */
function checkLength(algo: ChecksumAlgorithm): number {
  return algo === 'mod97-10' ? 2 : algo === 'none' ? 0 : 1;
}

/**
 * What the checksum is computed over. The Crockford check hashes the whole rendered core
 * (prefix + separators included), as the original did. The numeric checksums operate on
 * the digits only, so separators are stripped first.
 */
function checkInput(algo: ChecksumAlgorithm, core: string, format: IdFormat): string {
  if (algo === 'crockford-sha256') return core;
  return format.separator ? core.split(format.separator).join('') : core;
}

function computeCheck(algo: ChecksumAlgorithm, input: string): string {
  switch (algo) {
    case 'crockford-sha256':
      return crockfordSha256(input);
    case 'luhn':
      return luhn(input);
    case 'mod97-10':
      return mod97_10(input);
    case 'none':
    default:
      return '';
  }
}

// ---- Generate / validate --------------------------------------------------------------

export function generateResidentId(
  unitCode: string,
  format: IdFormat = DEFAULT_ID_FORMAT,
  countryCode?: string,
): string {
  const alphabet = alphabetOf(format);
  const total = format.groups.reduce((a, b) => a + b, 0);
  const bytes = randomBytes(total);
  let raw = '';
  for (let i = 0; i < total; i++) raw += alphabet[bytes[i] % alphabet.length];

  const segments: string[] = [];
  let k = 0;
  for (const g of format.groups) {
    segments.push(raw.slice(k, k + g));
    k += g;
  }

  const prefix = prefixOf(format, unitCode, countryCode);
  const parts = prefix ? [prefix, ...segments] : segments;
  const core = applyCase(parts.join(format.separator), format.case);

  const algo = format.checkDigit.enabled ? format.checkDigit.algorithm : 'none';
  if (algo === 'none') return core;

  const check = applyCase(computeCheck(algo, checkInput(algo, core, format)), format.case);
  return [core, check].join(format.separator);
}

export function isValidResidentId(id: string, format: IdFormat = DEFAULT_ID_FORMAT): boolean {
  const algo = format.checkDigit.enabled ? format.checkDigit.algorithm : 'none';
  // No checksum: nothing offline to verify beyond non-emptiness.
  if (algo === 'none') return id.length > 0;

  const clen = checkLength(algo);
  let core: string;
  let check: string;
  if (format.separator) {
    const idx = id.lastIndexOf(format.separator);
    if (idx < 0) return false;
    core = id.slice(0, idx);
    check = id.slice(idx + format.separator.length);
  } else {
    if (id.length <= clen) return false;
    core = id.slice(0, id.length - clen);
    check = id.slice(id.length - clen);
  }

  const expected = applyCase(computeCheck(algo, checkInput(algo, core, format)), format.case);
  return applyCase(check, format.case) === expected;
}

/**
 * A best-effort validation regex for integrators (MDA systems, capture UIs). Approximate
 * for `prefix.mode: unit`, since unit codes vary per deployment; exact for numeric formats.
 */
export function residentIdPattern(format: IdFormat = DEFAULT_ID_FORMAT): string {
  const alphabet = alphabetOf(format);
  const cls = `[${alphabet.replace(/[-\\\]]/g, '\\$&')}${format.case === 'lower' ? alphabet.toLowerCase() : ''}]`;
  const sep = format.separator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const body = format.groups.map((g) => `${cls}{${g}}`).join(sep);

  const prefixPart =
    format.prefix.mode === 'none'
      ? ''
      : format.prefix.mode === 'static'
        ? `${(format.prefix.value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${sep}`
        : format.prefix.mode === 'country'
          ? `[A-Za-z]{2}${sep}`
          : `[A-Za-z0-9-]+${sep}`; // unit: varies, so kept loose

  const algo = format.checkDigit.enabled ? format.checkDigit.algorithm : 'none';
  const checkPart = algo === 'none' ? '' : `${sep}${cls}{${checkLength(algo)}}`;

  return `^${prefixPart}${body}${checkPart}$`;
}
