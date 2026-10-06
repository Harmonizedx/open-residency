// SPDX-License-Identifier: Apache-2.0

/**
 * ISO 3166-2 subdivision codes: the notation, and a check against a country's table.
 *
 * ## Why this exists
 *
 * A deployment's unit `code` is its own key: records, resident IDs and credentials carry it, and
 * it is whatever the jurisdiction's statute or register already uses. Outside the deployment,
 * though, the same unit is named by ISO 3166-2, and that is the form the external vocabularies
 * expect: the EUDI PID and ISO 18013-5 `issuing_jurisdiction`, SEMIC Core Location
 * `adminUnitL1`, and the first segment of a national postcode where one is built on it.
 *
 * This module knows the SHAPE of an ISO 3166-2 code and nothing about any country. The codes
 * a given country assigns are data, shipped as `config/iso3166-2/<CC>.json` and read by the
 * loader; the core branches on none of them. That keeps the core free of jurisdiction-specific
 * knowledge, which is a property the conformance suite asserts.
 *
 * The check is a warning surface, not a gate: a jurisdiction may run wards or LGAs that ISO
 * does not enumerate, and refusing to start over that would be this software setting policy.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Subdivision suffixes assigned for one country, keyed by the part after `CC-`. */
export type SubdivisionTable = Readonly<Record<string, string>>;

const FULL_CODE = /^([A-Z]{2})-([A-Z0-9]{1,3})$/;

/**
 * Read a country's table from a directory of `<CC>.json` files. Returns undefined when no file
 * exists for the country, and throws when a file exists but is not a table -- a malformed data
 * file is a deployment error worth failing on, where a missing one is merely "not shipped".
 */
export function loadSubdivisionTable(dir: string, countryCode: string): SubdivisionTable | undefined {
  const cc = countryCode.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return undefined;
  const file = join(dir, `${cc}.json`);
  if (!existsSync(file)) return undefined;
  const raw: unknown = JSON.parse(readFileSync(file, 'utf8'));
  const table = (raw as { subdivisions?: unknown } | null)?.subdivisions;
  if (!table || typeof table !== 'object' || Array.isArray(table)) {
    throw new Error(`${file}: expected { "subdivisions": { "<suffix>": "<name>" } }`);
  }
  for (const [k, v] of Object.entries(table as Record<string, unknown>)) {
    if (!/^[A-Z0-9]{1,3}$/.test(k) || typeof v !== 'string') {
      throw new Error(`${file}: subdivision "${k}" must be a 1-3 character suffix mapped to a name`);
    }
  }
  return Object.freeze({ ...(table as Record<string, string>) });
}

/**
 * The comparison form of a unit code: upper-cased, trimmed, and with a leading ISO country
 * prefix removed when the whole string has ISO 3166-2 shape AND the prefix is this
 * deployment's country. `NG-NI`, `ng-ni` and `NI` all canonicalise to `NI` for a Nigerian
 * deployment. `GH-NI` does not: it keeps its prefix, so it can never be mistaken for Niger --
 * two countries reusing a suffix is ordinary, and dropping the prefix blindly would make them
 * one unit. Without a country to check against the prefix is kept too, which is the
 * conservative reading. A code that does not have ISO shape is returned as-is (upper-cased),
 * so a jurisdiction's own scheme (`WARD-07`, `0421`) is untouched.
 */
export function canonicalUnitCode(code: string, countryCode?: string): string {
  const upper = code.trim().toUpperCase();
  const m = FULL_CODE.exec(upper);
  if (!m) return upper;
  if (countryCode && m[1] === countryCode.trim().toUpperCase()) return m[2];
  return upper;
}

/** Is this string a well-formed ISO 3166-2 code (`CC-XXX`)? Says nothing about assignment. */
export function isIso3166_2Shape(code: string): boolean {
  return FULL_CODE.test(code.trim().toUpperCase());
}

export interface UnitCodeWarning {
  unitCode: string;
  message: string;
}

/**
 * Report unit codes a deployment declared that the country's table cannot vouch for.
 *
 * Checks, per unit: a declared `iso3166_2` must carry this country's prefix; a declared
 * `iso3166_2` must be assigned in the table; and, where no `iso3166_2` is declared, a `code`
 * that *looks* like a top-level ISO suffix but is not in the table is flagged, because the
 * likeliest cause is a typo rather than a deliberate local scheme. Units below the top level
 * are not checked -- ISO does not enumerate them. Returns nothing when no table is supplied.
 */
export function unitCodeWarnings(
  countryCode: string,
  units: ReadonlyArray<{ code: string; level: string; iso3166_2?: string }>,
  table: SubdivisionTable | undefined,
): UnitCodeWarning[] {
  const cc = countryCode.trim().toUpperCase();
  if (!table) return [];
  const out: UnitCodeWarning[] = [];
  for (const u of units) {
    if (u.iso3166_2) {
      const iso = u.iso3166_2.trim().toUpperCase();
      const m = FULL_CODE.exec(iso);
      if (!m) {
        out.push({ unitCode: u.code, message: `iso3166_2 "${u.iso3166_2}" is not of the form CC-XXX` });
        continue;
      }
      if (m[1] !== cc) {
        out.push({ unitCode: u.code, message: `iso3166_2 "${u.iso3166_2}" does not belong to ${cc}` });
        continue;
      }
      if (!(m[2] in table)) {
        out.push({ unitCode: u.code, message: `iso3166_2 "${u.iso3166_2}" is not assigned in ISO 3166-2:${cc}` });
      }
      continue;
    }
    if (u.level !== 'state' && u.level !== 'province' && u.level !== 'region') continue;
    const canon = canonicalUnitCode(u.code, cc);
    if (/^[A-Z]{2}$/.test(canon) && !(canon in table)) {
      out.push({
        unitCode: u.code,
        message: `code "${u.code}" is not a subdivision in ISO 3166-2:${cc}; declare iso3166_2 if it maps to one, or ignore if this is a local scheme`,
      });
    }
  }
  return out;
}
