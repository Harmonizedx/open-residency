# Working in this repository

## Conformance status: quote the suite, never a document

`npm run conformance:orcs` is the **only** authoritative statement of how far ORCS
implementation has got. It asserts all nine ORCS §15 acceptance criteria directly and prints
PASS / PARTIAL / FAIL with the finding id for each.

- **Run it before making any claim about conformance state.** Do not quote a pass/fail count
  from the implementation tracker, from an audit, from a commit message, or from earlier in
  the conversation. Those go stale within hours — this repo has had several
  sessions working concurrently, and the numbers have moved mid-session more than once.
- **A criterion is met when the suite says PASS.** Not when the model supports it, not when
  the migration landed, not when it typechecks. If an ORCS capability exists in the data model
  but no code path can exercise it end to end, that is PARTIAL, and saying otherwise
  overstates the system.
- **When a document and the suite disagree, the suite is right** — fix the document.
- The suite is deliberately **not** in `npm test` or CI while it is red. A permanently-failing
  required check trains people to ignore failing checks. It becomes a gate when it reaches
  all-PASS.

## Architecture: one deployment, one jurisdiction

A deployment is a **single subnational government**. `subjectRef` is unique within it — one
person, one residency record, here. This is deliberate and is not a limitation to be fixed.

ORCS §4.4's case (family home in Katsina, employment in Kano, study in Lagos) is satisfied
**across deployments**: Katsina's instance never holds the Kano relationship, it *verifies the
credential Kano issued*, through the federation trust list. The ecosystem holds the several
relationships; each deployment holds its own.

- Do not "fix" `subjectRef @unique` or add a composite multiplicity key. That was tried
  (`1937c6a`) and reversed — see `docs/adr/0004-one-deployment-one-jurisdiction.md`.
- There is no `relationshipType` / `purposeCode` / `status` on the record. Those came with the
  centralised design and were removed with it: a record here *is* this jurisdiction's residency,
  so there is no second kind for a type to distinguish. Do not reintroduce them as a way to
  represent multiplicity.
- Cross-jurisdiction awareness is a *verification* capability (`src/core/credentials/federation.ts`),
  never a storage one.
- A deployment holding another jurisdiction's relationships would be asserting authority it
  does not have, which ORCS §1.2 lists as a non-goal.

## Specification authority

- **ORCS-001 v1.0** (Core Specification) is **normative**. It defines conformance. A deviation
  is a conformance failure, not a design choice.
- **ORRA-001 v1.0** (Reference Architecture) is the **implementation blueprint**. It is
  advisory — a deviation needs an ADR, not a spec change.
- Decided 2026-08-02. PR #45, which declares "Consolidated Specification v7" the single source
  of truth, is superseded.
- Cite both by identifier and section (`ORCS §6.1`, `ORRA §8.1`), never by file path.

## Never commit the specification documents

`docs/OpenResidency_Core_Specification_ORCS_v1.0.docx` and
`docs/OpenResidency_Reference_Architecture_ORRA_v1.0.docx` are local working documents. They
are covered by `.gitignore` (`docs/*.docx`), and must not be force-added. Read them freely,
quote them by section, but never stage them.

## Verify before asserting

Claims in this repo are load-bearing — it is being prepared for Digital Public Good
submission, where a reviewer will test the README against the API.

- Count things by running a command, not by reading a document that counted them.
- Do not report "tests pass" or "typecheck clean" without having just run it. Files here
  change under you; a result from earlier in the session may already be false.
- Prefer under-claiming. The README was recently corrected for describing a relationship model
  the code did not implement; do not reintroduce that gap.

## Migration constraints (ORRA §15)

- Additive first. Migrations and compatibility adapters precede destructive schema changes.
- Do not delete working behaviour without a documented migration replacing it.
- `Resident` is retained as the compatibility surface for existing endpoints while the ORCS
  §4 entity decomposition proceeds.

## Where things are

| | |
| --- | --- |
| Implementation tracker (finding status, what landed) | `docs/architecture/IMPLEMENTATION-JOURNAL.md` |
| Phase 0 baseline audit + execution order | `docs/architecture/ORRA-PHASE0-BASELINE-AUDIT.md` |
| Decision records | `docs/adr/` |
| Conformance suite | `scripts/orcs-conformance.ts` |
| Residency domain + persistence port | `src/core/residency/` |
| Cross-jurisdiction trust (peer verification) | `src/core/credentials/federation.ts` |

`src/core/*` is framework-agnostic with no NestJS dependency. Keep it that way — NestJS is
only the delivery mechanism.