# 14. Identity links are a record with a history, not a column

- Status: Accepted — the implementation lands in the same change as this record.
- Date: 2026-09-30
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md), [ADR-0007](0007-residency-status-is-lifecycle.md), [ADR-0012](0012-subject-references-key-on-the-identifier.md)

## Context

Until this change, `subjectRef` -- the tokenized foundational identifier -- *was* the person.
It is the unique key of the residency record, the thing enrolment looks up, and the only
mapping between a national identifier and a resident that the register held. There was no
way to say "this reference was attached to the wrong record". An identity-link error could
be fixed only by editing the row in place or deleting one, and both destroy the history that
shows what happened and who did it.

ORCS §11 requires six operations on identity links -- LINK, UNLINK, RELINK, MERGE, SPLIT,
DISPUTE -- and §15 criterion 6 tests that every external identifier supports them. ORCS §7
names the remedy for a duplicate relationship caused by an identity-link error: "suspend
affected relationship, unlink and re-evaluate". [ADR-0012](0012-subject-references-key-on-the-identifier.md)
removed the largest *source* of such errors (the same number arriving through two routes)
but not the category: a clerk types a sibling's number, a duplicate is enrolled under a typo,
a sector system attaches its member number to the wrong resident. Finding G-05 recorded
this as the gate on migrating any populated register: a register imported with errors in it
needs a way to correct them that leaves a trail.

## Options considered

1. **Make `subjectRef` editable.** An operator corrects the column. Rejected: it loses the
   previous value, the reason, and the operator; it cannot express a dispute; and it gives the
   register no way to find a person by an identifier they *used* to hold.
2. **A Person entity with a one-to-many identity binding table, and the residency record
   keyed on the person.** The full ORCS §4.1 decomposition. Rejected for now, on ADR-0006's
   additive rule: it re-keys the register's central table and every read path with it, for a
   gain the third option delivers without touching `Resident`.
3. **An append-only link registry beside the record, consulted first by enrolment.** Chosen.

## Decision

**A person's identifiers are links in a registry with a history, and enrolment resolves
through the registry before it falls back to `subjectRef`.**

1. **Person = `residentId`.** ORCS §4.1 gives Person a stable internal identifier. In this
   deployment that is the residency record's `residentId`: one deployment is one jurisdiction
   (ADR-0004), so a person has at most one record here, and its id is the handle everything
   else already uses, including erasure, which keeps it.

2. **Only tokenized references are stored.** A link holds `identifierType` and
   `identifierRef`, the latter produced by the same HMAC as `subjectRef`, namespaced by type.
   A sector member number arriving at `POST /residency/{id}/identity-links` is tokenized on
   arrival and never stored, logged or returned. The registry holds nothing that correlates
   across deployments.

3. **Append-only.** A link that stops applying becomes UNLINKED and keeps its dates and
   reasons. RELINK, MERGE and SPLIT write a *new* link and chain it to the old one
   (`supersedes` / `supersededBy`). Every operation appends an event naming who did it and
   why. Nothing is deleted.

4. **Enrolment consults the registry first.** `issue()` asks the registry which person the
   identifier currently belongs to and acts on that record; only when the registry has no
   answer does it fall back to `subjectRef`, which is how every row written before the
   registry existed is found. A corrected mapping is therefore what the register acts on,
   not a note beside a lookup that still goes to the wrong row.

5. **DISPUTE restricts high-risk use.** While any of a person's links is DISPUTED,
   `issue()` refuses with `IDENTITY_LINK_DISPUTED` (recorded as a refusal, so it can be
   appealed) and wallet delivery answers `credential_request_denied`. Reading the record is
   not restricted. A dispute is closed by resolving it (the link was right), unlinking, or
   relinking.

6. **UNLINK of the foundational identifier follows ORCS §7's order.** The relationship is
   SUSPENDED first, then the record's `subjectRef` becomes a tombstone (`unlinked:<linkId>`)
   so the register stops matching an identity it has disowned. The reference lives on in the
   closed link; RELINK restores it to a record that has none, provided no other record now
   holds it.

7. **MERGE settles the duplicate row through the lifecycles that already exist.** Its
   relationship is ENDED with reason `MERGED_INTO_<survivor>` (ADR-0007), so the register
   says the standing continues elsewhere rather than that it stopped; its credential is
   REPLACED by the survivor's with `supersededBy` (ORCS §10). The row stays. Refused while any
   of the duplicate's links is DISPUTED.

8. **SPLIT restores identifiers, not relationships.** A terminal relationship is terminal.
   The restored person re-evaluates by enrolling again, which finds their row and opens a
   fresh relationship on it. That is ORCS §7's "re-evaluate", taken as a decision rather than
   as a side effect of reversing a different one.

9. **Roles follow the weight of the act.** LINK and DISPUTE: `registrar`. UNLINK and RELINK
   change whose identity a record is, the same authority as ending a relationship: `revoker`.
   MERGE and SPLIT rewrite which people exist in the register: `admin`.

**Deferred:** the §4.1 decomposition into `Person` and a binding table (option 2). The
registry's `personRef` is the seam it would use; nothing here has to be undone to get there.

## Why

**The history is the point.** A correction that erases what it corrected cannot be audited,
appealed, or reversed. Every operation here is somebody's decision, and the registry is the
record of those decisions in the order they were taken.

**Enrolment has to follow the correction.** A registry that records "this identifier now
belongs to that person" while enrolment keeps finding the old row would be documentation of
a bug, not a fix for it.

**Suspend before unlink, because that is the order ORCS gives and the safe one.** Unlinking
first would leave an ACTIVE relationship on a record the register no longer knows the
identity of, for the moments -- or the crash -- between the two writes.

**Not resurrecting a relationship on SPLIT is a feature.** The duplicate's relationship
was ended by a decision that turned out to be wrong; the right response is a fresh decision
about the person as they are now, with evidence, not a rollback that silently restores an
assessment nobody has re-made.

## Consequences

- `subjectRef` stays unique and stays the fallback. No existing row changes; rows written
  before the registry have their foundational link created the first time an operation
  needs one, from their own `subjectRef`, attributed to `migration:pre-registry-record`.
- Migrating a populated register is no longer blocked on this finding. Errors imported with
  it can be corrected with a trail.
- A tombstoned `subjectRef` is a new shape in the `Resident` table (`unlinked:<uuid>`), never
  matched by a foundational lookup and unique per link.
- Ten operator routes, in `docs/openapi.yaml` and the SDK.

## How this is verified

- `npm run smoke:identity-links` drives every operation and every refusal on the registry
  alone, then through the residency service: issuance links the foundational identifier, a
  disputed link refuses re-issuance until resolved, a merged identifier finds the survivor,
  a split restores it and re-enrolment opens a fresh relationship, and unlinking the
  foundational identifier suspends first.
- `npm run conformance:orcs` criterion 6 asserts the same through the residency service and
  reports PASS; the baseline records it, so a regression fails the build.
- `npm run test:store-e2e` round-trips every column of the three tables through the Prisma
  store on a real PostgreSQL and runs the registry unchanged on it.
- `scripts/identity-links-nest-e2e.cjs`, in the full-stack job, drives the ten routes over
  HTTP against the real application: guards, validation, tokenization of a raw identifier on
  arrival (the same card in two cases must link once), the audit trail, and enrolment
  following a merge, a split and an unlink.
