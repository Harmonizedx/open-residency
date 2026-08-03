# 6. Additive migration: `Resident` stays the facade while ORCS entities are extracted

- Status: Accepted
- Date: 2026-08-03
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md)

## Context

`Resident` is 26 columns holding what ORCS §4 models as several distinct things: a Person, an
IdentityBinding, a Jurisdiction reference, residence Evidence, an AssuranceProfile claim and a
Credential link. The Phase 0 audit calls this the central structural finding.

Every endpoint, the SDK, the reference UI, the admin console, the statistics export and
seventeen test suites read `Resident` today. ORRA §15 is explicit that migrations and
compatibility adapters precede destructive schema changes, and that working behaviour is not
deleted without a documented migration replacing it.

There is also direct evidence about the cost of getting this wrong. The centralised
relationship model ([ADR-0004](0004-one-deployment-one-jurisdiction.md)) was built, committed,
and reversed within a day. During that reversal two silent-overwrite defects surfaced — a store
that disagreed with its own listing about how many records existed, and a write path that let a
column default override a decision the service had already made. Both were found because the
old shape was still present to compare against.

## Options considered

1. **Big-bang normalisation.** Create the ORCS entities, migrate the data, delete `Resident`,
   update every caller in one change. Rejected: it makes the entire surface untestable until
   complete, and the reversal above shows the target shape is not yet stable enough to bet a
   single irreversible migration on.
2. **Database view named `Resident` over normalised tables.** Rejected: Prisma's typed client
   over a view is read-only in practice, so every write path would need rewriting immediately —
   the big-bang cost, without the big-bang's clean end state.
3. **Additive extraction with `Resident` retained as the write-through facade.** Chosen.

## Decision

**New ORCS entities are added alongside `Resident`, never in place of it. `Resident` remains
the compatibility surface every existing caller reads and writes, until each caller has been
moved deliberately and its tests pass against the new shape.**

The sequence for each entity:

1. **Add** the table. No caller changes. Nothing reads it yet.
2. **Backfill**, idempotently and re-runnably, from `Resident`.
3. **Dual-write** — the service writes both, `Resident` still authoritative for reads.
4. **Verify parity in CI** before any read moves.
5. **Switch reads** one caller at a time.
6. **Deprecate** the `Resident` columns only after a full release with no reads against them.

Constraints that hold throughout:

- The seventeen existing suites are the regression gate and must pass **unchanged** at every
  step. A step that needs them edited to stay green has changed behaviour, not shape.
- Per ADR-0004, `JurisdictionalRelationship` is **not** among the entities to extract. A
  deployment holds one residency per person and the `Resident` row *is* that relationship.
  Entities in scope: `Person`, `IdentityBinding`, `Jurisdiction`, `Address`, `Household`,
  `Evidence`, `AssuranceProfile`, `PolicyVersion`.
- No destructive schema change lands in the same commit as the additive one that precedes it.

## Consequences

**Good.** Every step is independently revertible, which the ADR-0004 reversal demonstrated is
not a theoretical need. The regression gate stays meaningful because it is never rewritten to
accommodate the change it is supposed to be guarding. Callers move on their own schedule.

**Bad.** The duplication is real while it lasts: two shapes, dual writes, and a parity check to
maintain. The temptation at each step will be to skip ahead to the clean end state, and the only
defence is that this record says not to. `Resident` also gets temporarily *larger* before it
gets smaller.

**Also.** "Full release with no reads" needs a way to know reads have stopped. Until there is
one, deprecation is judged by grep and code review rather than by telemetry, and should be
conservative — a column nobody is sure about stays.
