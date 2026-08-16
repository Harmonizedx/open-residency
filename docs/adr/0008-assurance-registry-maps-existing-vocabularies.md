# 8. The Assurance Registry maps the existing vocabularies rather than replacing them

- Status: Accepted — lands in the same change as the implementation it describes, so this file
  exists on `main` only once the change has landed.
- Date: 2026-08-16
- Relates to: [ADR-0003](0003-orcs-normative-orra-advisory.md),
  [ADR-0006](0006-additive-migration-resident-facade.md)

## Context

ORCS §8 opens with a prohibition: *"assuranceLevel MUST NOT be a free-text string. Every
assurance value must resolve to a governed profile in the Assurance Registry."* §8 defines five
dimensions — identity (IAL), authentication (AAL), federation (FAL), evidence (EA) and
credential (CA) — and §8.1 requires each identity source to publish a mapping to the canonical
profile carrying version, issuer, verification method and limitations.

Nothing resolved. `assuranceLevel` was one of four words (`none` / `basic` / `verified` /
`high`) with nothing behind them, so `'verified'` was a claim about a person with no record of
who decided it, by what method, at what revision, or what it did not cover.

Meanwhile the codebase already computed two assurance-shaped vocabularies carefully:

- `ResidenceAssuranceLevel` — `RAL0..RAL3`, with per-method ceilings, recency and unit-match
  downgrades (`src/core/proofing/residence.ts`).
- `BindingMethod` with `BINDING_RANK` — how strongly the applicant was proven to own the
  identity at enrolment (`src/core/proofing/binding.ts`).

And authentication assurance already existed in its own module, `src/core/sso/assurance.ts`,
producing an `acr` per sign-in.

## Options considered

1. **Replace `RAL*` and `BindingMethod` with the ORCS dimensions.** Rejected: it would discard
   working logic that several suites assert over, change enrolment behaviour, and violate the
   additive-migration constraint in [ADR-0006](0006-additive-migration-resident-facade.md).
2. **Add the ORCS dimensions alongside, computed independently.** Rejected: two systems
   deciding the same question drift, and the first disagreement between them is a defect nobody
   can adjudicate.
3. **Derive the ORCS dimensions from the existing vocabularies.** Chosen.

## Decision

**The registry is a closed vocabulary, and the canonical dimensions derive from the vocabularies
already in the tree.**

- `resolve()` returns null for any unregistered value. Callers treat null as a refusal, never as
  a reason to default. This is the whole requirement: a registry that minted a profile for an
  unrecognised word would leave the field free-text with extra ceremony.
- `BindingMethod` → IAL, following `BINDING_RANK` rather than inventing a second opinion about
  which method is stronger. A bare lookup is IAL1 however authoritative the registry, because
  anyone holding the number passes it.
- `RAL0..RAL3` → EA1–3. `RAL0` floors at EA1; ORCS defines no EA0, and the limitation is carried
  in the profile text instead of invented as a level.
- **Identity is the lower of what the provider can reach and what the binding achieved.** An
  IAL3-capable source used with no owner binding did not establish IAL3 for that applicant.
- **Authentication assurance never appears on a stored record.** It describes a sign-in event,
  is produced per session by `src/core/sso/assurance.ts`, and is carried in the id_token `acr`.
  The resolved result states its absence rather than omitting it silently.
- A profile must declare a version, an issuer and at least one dimension, or registration is
  refused. A duplicate profile id is refused rather than replacing the meaning of every value
  already resolved against it.
- The four legacy values are **aliased** to profiles, not removed. They are load-bearing across
  config validation, the residency service and the issued credential.

### Shipped provider mappings are the deployment's reading, not the authority's

Every mapping in `src/core/assurance/profiles.ts` says so in its own text. NIMC and UIDAI have
published no such mapping; §8.1 puts that obligation on the source, and a mapping invented here
on an authority's behalf would be a guess wearing a version number.

What ships is what can be said truthfully from each adapter's own behaviour: a registry lookup
proves a record exists, an authenticated flow proves the owner responded, an imported file
proves neither. `MOCK` resolves to a profile stating it establishes nothing and must not serve
real residents.

**A deployment is expected to replace the mapping for its own identity source.**

## Why

**Deriving beats duplicating.** The existing vocabularies encode decisions taken with care —
method ceilings, recency downgrades, the ordering in `BINDING_RANK`. Recomputing the same
judgement in a second place would produce two answers that agree until they do not.

**The closed vocabulary is the requirement, not the profiles.** It is tempting to read §8 as
"publish a profile table". The operative word is *resolve*: the specification is satisfied only
when an unrecognised value fails.

**Capping identity by binding prevents the fail-open default one layer up.** The bug fixed at
`0753829` was a config that declared no assurance level being credited with `'verified'`.
Letting a provider's advertised ceiling stand in for what an enrolment achieved would be the
same mistake wearing a governed profile.

**Separating identity from authentication is a §8 requirement, not tidiness.** Folding a
sign-in strength onto a person's record would assert a level that was true at some past login.

## Consequences

**Good.** Every assurance value resolves or is refused. Relying parties can read what a
verification did and did not establish, with the limitations attached. ORCS §15 criterion 3
passes.

**Bad.** The shipped mappings are provisional by construction and will read as authoritative to
someone who does not open them. Each carries its own disclaimer, which is mitigation rather than
a fix; the real fix is each authority publishing its own.

**Notable.** Because the conformance suite enrols through `MOCK`, its own run resolves to the
`test-only` profile and reports IAL1. Criterion 3 therefore passes against a deliberately weak
profile — correct, but worth knowing when reading the output.

## How this is verified

- `npm run smoke:assurance` — 35 assertions, wired into `npm test`. Covers the closed vocabulary
  (unregistered values, the empty string, a profile id used as a value), registration refusals
  (no version, no dimension, duplicate id, mapping naming an unknown profile), the derivations,
  and the identity cap.
- `npm run conformance:orcs` criterion 3, asserted **end to end** against the record the real
  `ResidencyService` issued rather than a fixture, checking resolution, governance, the §8.1
  mapping, dimension separation and the closed vocabulary.
- Mutation-checked: opening the vocabulary to a default, and folding authentication into a
  stored record, each turn criterion 3 red and name the sub-condition that broke.
- The HTTP surface was exercised against the booted application on a real PostgreSQL, because a
  registry no code path can reach is PARTIAL rather than PASS.
