# OpenResidency — Authoritative Specification

**The single source of truth for this project is
[`OpenResidency_Consolidated_Specification_v7.docx`](OpenResidency_Consolidated_Specification_v7.docx)**
(Core Product and Governance Specification, Consolidated v7).

Everything in this repository — code, schemas, APIs, credentials, tests and the other
docs — is governed by, and should be read as inferring to, that document. Where any other
document disagrees with it, **v7 wins.**

## What v7 governs (index, not a substitute — read the docx for the normative text)

- **Purpose-scoped residency.** A person holds *many* simultaneous, purpose-scoped
  `ResidencyRelationship`s (household, employment, education, tax nexus, …), each with its
  own policy, evidence and lifecycle. There is no single "primary jurisdiction."
- **Deterministic policy evaluator + DecisionTrace as the product core.** Five clause
  states (`SATISFIED`, `NOT_SATISFIED`, `NOT_APPLICABLE`, `DISCHARGED`, `INDETERMINATE` —
  boolean coercion prohibited), a closed predicate vocabulary, and a signed, replayable,
  atomically-persisted `DecisionTrace`.
- **Sealed rights floor.** `NationalConstraint` (sealed) → `RulePack` → `ProgrammeOverlay`;
  lower layers cannot weaken nationally mandated privacy, appeal, inclusion or assurance
  protections. Origin/indigene/ethnicity must never affect ordinary residency; no single
  document (e.g. a utility bill) may be the sole evidence route.
- **Closed vocabularies, semantically versioned.** DecisionOutcome, ClauseClass, AppealOutcome,
  relationshipType, assurance profiles and purpose codes are closed and version-pinned;
  historical decisions replay under the exact vocabulary version in their trace.
- **Federated SSO, optional and replaceable.** OpenResidency is the residency/policy
  authority; an existing IdP (e.g. KSAuth, MOSIP, a national eID) remains the
  authentication/session authority. Account status is independent from residency status.
- **Registries.** Consent, Legal Basis, Identity Link, Service, and DPIA registries, with
  versioned read/validate APIs.
- **Credential profile.** W3C VC 2.0, VC-JWT, EdDSA/Ed25519, online + controlled offline
  verification, and a distinct governed DecisionTrace signing-key lifecycle.
- **Release-one scope discipline.** Core + evaluator/trace + auth integration profile +
  credentials + registries + appeals ship first; general event/exchange/connector
  infrastructure and life-event orchestration are **roadmap**.

## Implementation posture (from v7)

**Extend the existing evaluator; do not replace it or build a parallel engine.** Before any
production change, the Phase 0 gate applies: inventory the real files implementing the
evaluator/Decision, lock current behaviour with regression tests, and record the smallest
extensions — see `docs/architecture/` once that gate has run.

## Superseded documents

The following earlier design notes are **superseded by v7** and retained only as history;
they are not authoritative and must not be used to drive implementation:

- The standalone residency-policy platform blueprint (`RESIDENCY-POLICY.md`) — folded into
  and superseded by v7's §4 (evaluator) and §10 (delivery shape).
- Any earlier "reference architecture" or "policy-engine blueprint" notes.
