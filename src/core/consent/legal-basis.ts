// SPDX-License-Identifier: Apache-2.0

/**
 * The Legal Basis Registry (ORCS §9).
 *
 * §9 requires that every `legalBasisReference` resolve through this registry. That phrasing
 * matters: it is the same requirement §8 makes of assurance values, for the same reason. A
 * consent record carrying `legalBasisReference: "the law"` documents nothing -- nobody can
 * tell which instrument was relied on, who relies on it, or whether it is still in force. So
 * `resolve` is a CLOSED vocabulary and returns null for anything unregistered, and every
 * caller treats null as a refusal rather than a default.
 *
 * Two reads, deliberately different:
 *
 *   - `resolve(id)` answers "may processing proceed on this basis, now". It refuses a
 *     deactivated basis and one outside its effective window.
 *   - `get(id)` answers "what was this basis". It returns the record whatever its state,
 *     because a consent granted in 2026 under a since-repealed by-law must stay readable --
 *     an auditor asking what authority was relied on needs the answer, and deactivating a
 *     basis must not retroactively blank the history that cites it.
 *
 * A registry that conflated the two would either let a repealed instrument keep authorising
 * processing, or erase the record of what was relied on. Both are worse than the free-text
 * string this replaces.
 */

/**
 * The lawful bases for processing.
 *
 * The vocabulary is the one common to NDPA 2023 s.25, GDPR Art.6 and Convention 108+ Art.5,
 * which is why it is closed here rather than free-text: these are the bases those regimes
 * recognise, and a deployment that needs a different one is making a claim its regulator
 * has to have agreed to.
 */
export type LegalBasisKind =
  | 'consent'
  | 'contract'
  | 'legal_obligation'
  | 'vital_interests'
  | 'public_task'
  | 'legitimate_interests';

/**
 * A registered basis for processing.
 *
 * `instrument` is what makes the record auditable -- the statute, regulation, by-law or
 * executive instrument being relied on, cited well enough that a reader can find it. It is a
 * string rather than a structured citation because legal citation formats differ by
 * jurisdiction and imposing one here would constrain deployments for no gain, which is the
 * same call `appealPath` makes in the credential lifecycle.
 */
export interface LegalBasis {
  /** Stable identifier, cited by consent records. */
  id: string;
  kind: LegalBasisKind;
  /** Human-readable name, for operator interfaces and audit output. */
  name: string;
  /** The instrument relied on: statute, regulation, by-law, or the consent itself. */
  instrument: string;
  /** The jurisdiction whose law this is. */
  jurisdiction: string;
  /** The controller relying on it. */
  controller: string;
  /** Revision of this entry. A basis restated under an amended instrument is a new version. */
  version: string;
  /** ISO date from which it may be relied on. */
  effectiveFrom: string;
  /** ISO date after which it may not, when the instrument itself is time-limited. */
  effectiveTo?: string;
  /** Set when the basis is withdrawn. A deactivated basis stays readable; see `get`. */
  deactivatedAt?: string;
  deactivationReason?: string;
  deactivatedBy?: string;
}

export type DeactivateOutcome = { ok: true; basis: LegalBasis } | { ok: false; reason: string };

/**
 * The one basis every deployment can rely on without declaring local law.
 *
 * Consent is a lawful basis in each of the regimes this vocabulary is drawn from, so shipping
 * it is not a guess about anybody's statute book. Every OTHER basis is jurisdiction-specific
 * and is left to the deployment to declare -- inventing a "public task" entry on a
 * government's behalf would be exactly the guess-wearing-a-version-number that the assurance
 * profiles refuse to make.
 */
export const CONSENT_LEGAL_BASIS_ID = 'orcs:legal-basis:consent';

export function defaultLegalBases(jurisdiction: string, controller: string): LegalBasis[] {
  return [
    {
      id: CONSENT_LEGAL_BASIS_ID,
      kind: 'consent',
      name: 'Consent of the data subject',
      instrument:
        'The consent recorded in this register. Recognised as a lawful basis by NDPA 2023 ' +
        's.25(1)(a), GDPR Art.6(1)(a) and Convention 108+ Art.5(2).',
      jurisdiction,
      controller,
      version: '1.0',
      effectiveFrom: '1970-01-01',
    },
  ];
}

/**
 * The bases a deployment starts with: the built-in consent basis, plus whatever local law it
 * declared.
 *
 * Takes a structural shape rather than importing the config type, so this module stays free
 * of any dependency on the config layer -- which imports `CONSENT_LEGAL_BASIS_ID` from here,
 * and a cycle between the two would be a poor trade for one type import.
 */
export function legalBasesForDeployment(input: {
  jurisdiction: string;
  controller: string;
  declared?: Array<
    Omit<LegalBasis, 'controller' | 'version'> & { controller?: string; version?: string }
  >;
}): LegalBasis[] {
  return [
    ...defaultLegalBases(input.jurisdiction, input.controller),
    ...(input.declared ?? []).map((d) => ({
      ...d,
      controller: d.controller ?? input.controller,
      version: d.version ?? '1.0',
    })),
  ];
}

export class LegalBasisRegistry {
  private bases = new Map<string, LegalBasis>();

  constructor(bases: LegalBasis[] = []) {
    for (const b of bases) this.register(b);
  }

  /**
   * Add a basis.
   *
   * Rejects a duplicate id, because silently replacing one would change the meaning of every
   * consent already citing it. Rejects an entry missing instrument, controller, jurisdiction
   * or version: those four are what make it a governed record rather than a label, and
   * admitting an entry without them would satisfy the letter of §9 while losing its point.
   */
  register(basis: LegalBasis): void {
    if (this.bases.has(basis.id)) {
      throw new Error(`Legal basis "${basis.id}" is already registered`);
    }
    const missing = (['instrument', 'controller', 'jurisdiction', 'version'] as const).filter(
      (f) => !basis[f]?.trim(),
    );
    if (missing.length > 0) {
      throw new Error(
        `Legal basis "${basis.id}" must declare ${missing.join(', ')} (ORCS §9); an ` +
          'unattributed basis is not something a regulator can check.',
      );
    }
    if (!Number.isFinite(Date.parse(basis.effectiveFrom))) {
      throw new Error(`Legal basis "${basis.id}" has an unparseable effectiveFrom`);
    }
    this.bases.set(basis.id, basis);
  }

  /**
   * The basis if it may be relied on right now, else null.
   *
   * Null covers three different situations on purpose -- unregistered, deactivated, outside
   * its window -- because the caller's response to all three is identical: refuse. A caller
   * that wants to tell them apart is auditing rather than processing, and should use `get`.
   */
  resolve(id: string, now: Date = new Date()): LegalBasis | null {
    const basis = this.bases.get(id);
    if (!basis) return null;
    if (basis.deactivatedAt) return null;
    const at = now.getTime();
    if (Date.parse(basis.effectiveFrom) > at) return null;
    if (basis.effectiveTo && Date.parse(basis.effectiveTo) <= at) return null;
    return basis;
  }

  /** The record whatever its state. History that cites a repealed basis must stay readable. */
  get(id: string): LegalBasis | null {
    return this.bases.get(id) ?? null;
  }

  list(): LegalBasis[] {
    return [...this.bases.values()];
  }

  /**
   * Withdraw a basis.
   *
   * Refused without a reason and an authority rather than recorded blank, on the same
   * reasoning as a credential revocation: withdrawing the lawful basis for processing stops
   * every consent citing it, and a decision with that reach has to be attributable to
   * somebody. There is no reactivation -- a basis relied on again after withdrawal is a new
   * entry with its own version, so the gap during which processing was not authorised stays
   * visible instead of being closed over.
   */
  deactivate(
    id: string,
    input: { reason: string; authority: string; at?: string },
  ): DeactivateOutcome {
    const basis = this.bases.get(id);
    if (!basis) return { ok: false, reason: 'UNKNOWN_LEGAL_BASIS' };
    if (basis.deactivatedAt) return { ok: false, reason: 'LEGAL_BASIS_ALREADY_DEACTIVATED' };
    if (!input.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED_FOR_DEACTIVATION' };
    if (!input.authority?.trim()) {
      return { ok: false, reason: 'AUTHORITY_REQUIRED_FOR_DEACTIVATION' };
    }
    const updated: LegalBasis = {
      ...basis,
      deactivatedAt: input.at ?? new Date().toISOString(),
      deactivationReason: input.reason.trim(),
      deactivatedBy: input.authority.trim(),
    };
    this.bases.set(id, updated);
    return { ok: true, basis: updated };
  }
}
