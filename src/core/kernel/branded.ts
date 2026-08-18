// SPDX-License-Identifier: Apache-2.0

/**
 * The shared kernel: types every part of the domain agrees on, that depend on nothing.
 *
 * Small on purpose. A shared kernel that grows becomes a second god object with a nicer
 * name, so what lands here has to be genuinely common AND genuinely dependency-free — a
 * vocabulary, not a utility drawer.
 */

declare const brand: unique symbol;

/**
 * A string that has been checked, and cannot be confused with one that has not.
 *
 * `Branded<string, 'X'>` is assignable TO `string` but not FROM it, so the type system
 * permits reading one as text while refusing to accept arbitrary text in its place. The
 * brand exists only at compile time: at runtime these are ordinary strings, with no wrapper
 * to allocate and nothing to serialise differently.
 */
export type Branded<T, B extends string> = T & { readonly [brand]: B };

/**
 * A resident's human-facing identifier.
 *
 * Distinguished from `subjectRef` (the tokenised foundational reference) and from every
 * other identifier in the system, because those distinctions are load-bearing and were
 * previously kept only by naming discipline. `residentId: string` and `subjectRef: string`
 * are the same type to a compiler: swapping them at a call site is a silent change that
 * reads correctly, passes review, and stores one person's residency under another's
 * reference.
 *
 * ADR-0010 draws the same line for authentication references. This makes it checkable.
 */
export type ResidentId = Branded<string, 'ResidentId'>;

/**
 * Assert that a string is a resident id.
 *
 * Deliberately NOT a validator. Format is a jurisdiction's choice — `IdFormat` in
 * core/residency/resident-id.ts covers numeric schemes, Crockford base32, Luhn and
 * mod97-10 — so the only honest check available without that config is that the value is
 * non-empty. Validation against a format belongs where the format is known, and pretending
 * otherwise here would put a second, weaker rule in the codebase for the same question.
 *
 * What this gives is a single, greppable place where an unchecked string becomes a
 * ResidentId. Every such conversion is a boundary crossing, and boundary crossings should
 * be visible.
 */
export function asResidentId(value: string): ResidentId {
  if (!value) {
    throw new Error('asResidentId received an empty string');
  }
  return value as ResidentId;
}

/** Convert without the empty check, for values already known to be ids (database rows). */
export function unsafeResidentId(value: string): ResidentId {
  return value as ResidentId;
}