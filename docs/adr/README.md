# Architecture Decision Records

Material deviations and technology choices, one record each. ORRA-001 §15 requires an ADR for
every one of them; these are the tracked, citable copies.

Numbering starts at 0003 — PR #44 claims 0001 and 0002 for the hexagonal architecture.

| ADR | Decision | Status |
| --- | --- | --- |
| [0003](0003-orcs-normative-orra-advisory.md) | ORCS is normative, ORRA is advisory — disposition of the v7 consolidated spec | Accepted |
| [0004](0004-one-deployment-one-jurisdiction.md) | One deployment, one jurisdiction: multiplicity lives in the ecosystem, `subjectRef @unique` stays | Accepted |
| [0005](0005-enrolment-capture-layer.md) | Enrolment capture is a bounded, jurisdiction-declared layer; the credential stays minimal | Proposed |
| [0006](0006-additive-migration-resident-facade.md) | Additive migration: `Resident` stays the write-through facade while ORCS entities are extracted | Accepted |
| [0007](0007-residency-status-is-lifecycle.md) | Residency status is lifecycle, not multiplicity: a record carries `status` and validity, records type and purpose, and never reads either. Permanent until ended | Accepted |
| [0008](0008-assurance-registry-maps-existing-vocabularies.md) | The Assurance Registry is a closed vocabulary; ORCS §8 dimensions derive from the existing `RAL*` and `BindingMethod` rather than replacing them | Accepted |
| [0009](0009-legal-basis-registry-closed-vocabulary.md) | The Legal Basis Registry is a closed vocabulary; a consent that cannot name its controller, categories, evidence and basis is refused rather than written blank | Accepted |
| [0010](0010-authentication-refs-are-not-residency-identities.md) | An upstream authentication reference is not a residency identity: `subjectRef` is always the foundational provider's, and a pairwise OP subject cannot substitute | Accepted |

## Pending

Recorded here so the queue survives independently of any working note:

| Decision | Blocking |
| --- | --- |
| Jurisdiction as a registry versus the current YAML configuration model | Phase 1 |
| Event architecture kept separate from the audit hash chain | Phase 4 |

## Conventions

- Filename `NNNN-kebab-title.md`; heading `# N. Title`.
- Metadata as a bullet list: `Status`, `Date`, and `Relates to` when it builds on another.
- `Status` is `Proposed` until the change it describes lands, then `Accepted`. A reversal is a
  new superseding ADR, never an edit to the original — see 0004 reversing the centralised model.
- Every ADR states **how it is verified**, so the decision is checkable rather than asserted.
