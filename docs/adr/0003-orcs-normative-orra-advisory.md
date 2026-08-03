# 3. ORCS is normative, ORRA is advisory

- Status: Accepted
- Date: 2026-08-02

## Context

Two specifications govern this project, and until now the repository did not say which one
wins, or what it means to disagree with either.

- **ORCS-001 v1.0** — *OpenResidency Core Specification.* Domain entities, registries, closed
  vocabularies, state machines, and nine acceptance criteria in §15.
- **ORRA-001 v1.0** — *OpenResidency Reference Architecture.* Logical components, repository
  topology, flows, connector families, an event envelope, and a seven-phase roadmap.

ORRA §15 states the rule itself: *"treat ORCS as normative and ORRA as the implementation
blueprint."* This ADR records that as a repository decision, with the consequences spelled
out, because "normative" and "blueprint" only mean something if a disagreement with each has
a different remedy.

There is also a conflict to settle. An earlier consolidated specification (v7) was proposed as
"the single source of truth", with the rule that where any other document disagrees, v7 wins.
ORCS/ORRA v1.0 were authored afterwards. The two are not reconcilable: v7 centres a
DecisionTrace-as-product model, five clause states, a closed DecisionOutcome vocabulary and a
DPIA registry, **none of which appear in ORCS**. Leaving both in force would mean the
codebase could not be said to conform to anything.

## Options considered

1. **v7 is the single source of truth**, as PR #45 proposes. Rejected: v7 centres a model the
   codebase does not implement and was not going to, and ORCS/ORRA were authored afterwards.
2. **Both in force, reconciled case by case.** Rejected: with two documents claiming primacy
   and no rule for disagreement, "are we conformant?" has no answer, and every design argument
   can cite whichever specification suits it.
3. **ORCS normative, ORRA advisory** — ORRA §15 states this rule itself. Chosen.

## Decision

**ORCS-001 v1.0 is normative. ORRA-001 v1.0 is advisory. The consolidated v7 specification is
superseded and retained only as history.**

| | ORCS | ORRA |
|---|---|---|
| Authority | Normative — defines conformance | Advisory — defines a recommended construction |
| A deviation is | a conformance failure | a design decision |
| Remedy | change the code, or amend the specification | record an ADR |
| Verified by | `npm run conformance:orcs` | ordinary integration tests |
| When silent | fall through to ORRA | fall through to engineering judgement |

Worked example. ORCS §12 requires that events "MUST use a canonical, versioned envelope and
contain references rather than unnecessary sensitive payloads." ORRA §8.1 supplies a specific
envelope with `specVersion`, `correlationId`, `legalBasisReference` and so on. Renaming those
fields, or adding our own, is an ADR. Shipping an unversioned envelope carrying raw personal
data is a conformance failure.

### Conformance is machine-checked

ORCS §15's nine acceptance criteria are asserted by `scripts/orcs-conformance.ts`
(`npm run conformance:orcs`). Conformance is what that suite reports, not what any document
claims — including this one, which is why no pass/fail count is quoted here. Run the command.

It is red today, and deliberately excluded from CI while it is red, because a
permanently-failing required check trains people to ignore failing checks. It becomes a
required gate, exiting non-zero on any non-PASS, when the migration completes.

### The specification sources are not committed

ORCS and ORRA are circulated separately and are held as local working documents. They are
cited by identifier and section (`ORCS §8`, `ORRA §14`), never by committed file path, and
`.gitignore` keeps them and the derived gap analysis out of `git add -A`. A reader without the
sources can still follow every citation to a numbered section.

## Consequences

**Good.** There is one authority, so "are we conformant?" has one answer and a command that
produces it. Deviations are separated into two kinds with different costs, which stops
architectural preference being argued as if it were a conformance obligation. Retiring v7
removes a specification whose model the code does not implement and was not going to.

**Bad.** Conformance is measured against a document most readers of this repository cannot
open. The mitigation is that findings and criteria are restated in full wherever they are
relied on — in the conformance suite's output and in each ADR — so the repository is
self-explanatory even where the sources are not present.

**Also.** ORCS silence is not permission. Where ORCS says nothing and ORRA does, ORRA governs
by fall-through; where both are silent, the choice is ours and needs an ADR only if material.

## Compliance

- `scripts/orcs-conformance.ts` — the §15 gate.
- Any pull request deviating from ORRA adds an ADR.
- Any pull request that cannot satisfy ORCS states which criterion and why, in the commit
  message, rather than adjusting the criterion.