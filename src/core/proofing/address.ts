// SPDX-License-Identifier: Apache-2.0

/**
 * An address, for the jurisdictions where residency *is* address registration.
 *
 * ## Why this exists
 *
 * Residence proof here was defined as administrative-unit matching: evidence reconciles to a
 * unit, the unit must equal the claimed one. That is what residency means in Nigeria, and in
 * much of Africa and South Asia, where a great deal of housing has no formal street address at
 * all.
 *
 * It is not what residency means everywhere. Under Germany's Bundesmeldegesetz every resident
 * must register their ADDRESS within fourteen days of moving, and that registration is what
 * unlocks a residence permit, a bank account and benefits. Japan's jūminhyō certifies a current
 * residential address. The Nordic population registers track addresses continuously and have
 * largely replaced the census. In those systems "which state do you live in" is not a
 * lighter-weight residency -- it is not residency.
 *
 * So the anchor is a jurisdiction's choice, in the way everything else jurisdiction-shaped here
 * already is: the foundational identity source is an adapter, assurance resolves through a
 * governed registry, who decides is derived from configured methods. This is the same pattern
 * applied to the thing residency is anchored to.
 *
 * ## What this deliberately does NOT do
 *
 * It does not parse, geocode, or canonicalise addresses. Address formats are jurisdictional to
 * their bones -- house-number-first or last, postcode present or absent, script and
 * transliteration, informal descriptors that are the only locator anyone has. A core that
 * imposed one shape would re-commit the exact error this module exists to correct, just in the
 * other direction.
 *
 * Lines are stored as the jurisdiction records them and compared through a deliberately naive
 * normalisation. A deployment needing gazetteer-grade matching normalises before it gets here
 * and passes the result; the core will not pretend to have solved a problem it has not.
 */

export interface ResidenceAddress {
  /**
   * Address lines exactly as the jurisdiction records them. Never parsed by the core.
   *
   * A single line is fine. So is a descriptor that is not a street address at all -- "third
   * compound past the borehole, Rigasa ward" is the only locator some residents have, and a
   * register that refuses it excludes them while claiming to be about inclusion.
   */
  lines: string[];
  /** Where the jurisdiction uses one. Absent is normal, not a gap. */
  postalCode?: string;
  /**
   * The administrative unit this address sits within.
   *
   * Kept even under address anchoring, because jurisdiction scoping does not stop mattering:
   * a German municipality still needs to know the address is in ITS municipality. Address
   * anchoring is stricter than unit anchoring, never a replacement for it.
   */
  adminUnit?: string;
}

/**
 * A comparison key. Lowercased, punctuation dropped, whitespace collapsed, lines joined.
 *
 * Naive on purpose, and documented as such rather than quietly approximate. It catches the
 * differences that are genuinely noise -- capitalisation, stray commas, double spaces, a
 * trailing full stop -- and nothing else. "12 Ahmadu Bello Way" and "12 Ahmadu Bello Wy" are
 * different addresses to this function, because deciding they are the same is a judgement about
 * one country's abbreviations that a core serving every country has no business making.
 */
export function addressKey(address: ResidenceAddress): string {
  const parts = [...address.lines, address.postalCode ?? ''];
  return parts
    .join(' ')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Do two addresses compare equal under that normalisation? */
export function addressesMatch(a?: ResidenceAddress, b?: ResidenceAddress): boolean {
  if (!a || !b) return false;
  const ka = addressKey(a);
  const kb = addressKey(b);
  // An address that normalises to nothing -- empty lines, punctuation only -- matches nothing,
  // including another empty one. Otherwise two blank submissions would "agree".
  if (!ka || !kb) return false;
  return ka === kb;
}

/**
 * What a jurisdiction anchors residency to.
 *
 * `unit` -- residence is membership of an administrative unit. Nigeria, and most places where
 * addressing is partial or informal.
 *
 * `address` -- residence is registration at a specific address, and the unit must still agree.
 * Germany, Japan, the Nordics, Korea. Strictly stronger than `unit`.
 *
 * Defaults to `unit`, so every existing deployment and config keeps its current meaning.
 */
export type ResidenceAnchor = 'unit' | 'address';
