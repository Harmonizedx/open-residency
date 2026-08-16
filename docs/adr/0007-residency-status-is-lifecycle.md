# 7. Residency status is lifecycle, not multiplicity

- Status: Accepted — the implementation lands in the same change that flips this line.
- Date: 2026-08-16
- Amended: 2026-08-16 — two amendments, and the open question resolved; see **Amendments**
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md), [ADR-0006](0006-additive-migration-resident-facade.md)

## Context

[ADR-0004](0004-one-deployment-one-jurisdiction.md) reversed the centralised relationship model
and removed `relationshipType`, `purposeCode` and `status` together, reasoning that a record in
this deployment *is* this jurisdiction's residency, so "there is no second kind for the type to
distinguish".

Two of those three removals were right. The third conflated two independent questions:

1. **How many** relationships a deployment holds per person. ADR-0004 settles this: one, with
   multiplicity federated across deployments. That decision stands and this record does not
   disturb it.
2. **What a single relationship record must say about itself over time.** `status` answers this
   one. It is a fact about time, not about multiplicity, and it is needed whether a deployment
   holds one relationship or a hundred.

ORCS §4.3 requires each relationship to specify status and validity among ten attributes, and
§6.2 defines the state machine. Neither requirement is conditional on holding more than one
relationship.

### What the code does today

- `ResidentRecord` (`src/core/residency/ports.ts`) carries `createdAt` and `erasedAt`. There is
  no other state on the record.
- `ResidencyService.revoke()` flips a bit in the credential status list and never touches the
  record.
- `ResidencyService.issue()` returns `exists` for anyone already in the register, so a
  re-enrolment returns the original record — original unit, original evidence, original
  assurance — with no re-evaluation.
- `GET /residency/{residentId}` returns `subnationalUnit`, `assuranceLevel`, `provisional` and
  `createdAt`. Nothing it returns can change.

The consequence is that **a person who leaves the jurisdiction cannot be recorded as having
left.** Revoking their credential is the only available action, and it conflates "this credential
is dead" with "this person is no longer resident". `revoke()` preserves no reason (ORCS §10,
finding G-07), so the audit trail cannot separate the two either. A move between wards inside the
jurisdiction is unrecordable for the same reason.

## Options considered

1. **Leave it.** Rejected: ORCS §4.3 is a MUST, and a register that asserts a residency it can
   never withdraw propagates stale trust into every service that depends on it.
2. **Reintroduce `relationshipType`, `purposeCode` and `status` as gating fields**, the shape
   ADR-0004 removed. Rejected: purpose-scoped residency converts foundational trust into
   permission, for the reason given below.
3. **Add lifecycle state only, omitting type and purpose.** Rejected on amendment — §4.3 makes
   both MUSTs, and the objection was always to reading them, not to holding them. See
   **Amendment 1**.
4. **Add lifecycle state and validity; record type and purpose as inert fields.** Chosen.

## Decision

**A residency record carries lifecycle status and validity. It records type and purpose, and
must never read either in a decision path.**

- `status` is drawn from the ORCS §6.2 vocabulary, limited to the transitions a
  single-jurisdiction deployment can actually perform.
- `validity` is recorded as effective dates. ORCS §4.3 requires validity independently of
  whether anything lapses automatically — and per Amendment 2, nothing does.
- `subjectRef @unique` is unaffected. This adds columns, never a row. Multiplicity remains
  federated exactly as ADR-0004 decided, and nothing here permits a second record per person.
- `type` and `purpose` **are recorded**, because ORCS §4.3 lists both among the ten attributes
  every relationship MUST specify. They are inert: no code path may branch on either, and no
  API may accept one as a filter or a gate. **The reason a person resides somewhere must not
  determine what they can reach** — but that is a constraint on *reads*, not grounds for
  omitting a required field. Residency here is foundational trust; services tied to residence
  run their own eligibility rules over it. Making purpose a gate would convert foundational
  trust into purpose-scoped permission, which is a materially different and worse system.
- The read prohibition is enforced the way `src/core/proofing/residence.ts` already enforces
  the origin invariant: as an invariant with a test that fails if it is violated, not as a
  convention.
- A single-jurisdiction deployment records `GENERAL_RESIDENCY` while active and
  `FORMER_RESIDENCY` once ended (ORCS §6.1 supplies both).

## Why

**The principle is already an invariant elsewhere.** Origin and indigeneity can never be an
accepted residence method (`src/core/proofing/residence.ts`), precisely because a reason for
belonging must not determine access to services. Status is the opposite kind of fact: it asks
whether the relationship holds *now*, not why it was granted.

**The broader the trust, the more its currency matters.** Every service tied to residence
inherits whatever the register says. A register that can only ever say "resident, since" hands
foundational trust to a person who left years ago, and no service downstream has any way to know.

**Ending a residency and revoking a credential are different acts.** One is a statement about a
person's relationship to a jurisdiction; the other is a statement about a key. Collapsing them
into a single lever means neither can be audited on its own terms.

## Consequences

**Good.** Leaving becomes expressible. Re-enrolment can re-evaluate rather than return a stale
record. Credential revocation stops carrying two meanings.

**Bad.** The idempotency contract of `issue()` changes: an `exists` result must take status into
account. Existing records need a default of `ACTIVE`, added additively under ORRA §15 and
[ADR-0006](0006-additive-migration-resident-facade.md).

**Resolved (Amendment 2).** Residency is **permanent until ended**. Validity dates are recorded
regardless — §4.3 requires them — but nothing lapses on its own.

## Amendments

Both were made before acceptance. The Proposed text is preserved in git history.

### Amendment 1 — type and purpose are recorded, not omitted

The Proposed decision read *"It does not carry a relationship type or a purpose."* ORCS §4.3
states that each relationship **MUST** specify *type, purpose*, jurisdiction, status, validity,
policy version, evidence references, assurance profile, issuer and decision provenance. Omitting
two of those ten is a deviation from a normative MUST, and ORCS deviations are conformance
failures rather than design choices ([ADR-0003](0003-orcs-normative-orra-advisory.md)). The
Proposed record did not declare it as a deviation, which is how it would have had to stand.

The principle being protected survives intact, because it was always a claim about reads: *the
reason a person resides somewhere must not determine what they can reach.* That forbids
branching on purpose. It does not require the field to be absent. The Proposed text reached
this itself one bullet later — *"Recording a reason as inert metadata is permitted. Reading it
in any decision path is not"* — which contradicted its own headline. This amendment keeps the
bullet and drops the headline.

### Amendment 2 — permanent until ended, with validity recorded

The Proposed record left open whether residency expires and renews, and suggested that if it
does not, *"status alone suffices."* Against §4.3 that option does not exist: validity is a MUST
whether or not lapsing is automatic. The real question is narrower — does anything expire *on
its own*.

It does not, for two reasons.

**Auto-expiry falls hardest on the people the register exists to include.** The population that
struggles to re-prove residence on a schedule is the population without documents. An expiring
register turns an inclusion mechanism into a recurring administrative burden borne by exactly
those least able to carry it, and it withdraws foundational trust from people who never stopped
being resident — a silent failure, invisible until a service refuses them.

**Enrolment drives would create cohort-wide expiry.** Everyone registered in one campaign lapses
on the same day years later, producing a mass re-enrolment event no jurisdiction has staffing
for.

Freshness is still a real concern, and the credential already answers it: `validityDays` (1095
in `config/countries/ng.yaml`) gives a three-year re-contact cadence without the register ever
withdrawing a residency nobody asked it to withdraw. **The credential expires; the relationship
does not.** Relying parties apply their own freshness tolerance over the recorded dates, which
is the split this record already argues for — foundational trust in the register, eligibility
rules in the services.

`EXPIRED` stays in the §6.2 vocabulary as a reachable state for a deployment that legislates
fixed-term residency. Nothing in this implementation drives a record into it.

## How this is verified

All four are implemented. `npm run smoke:lifecycle` covers 1-4 below (55 assertions), and
criterion 1 was mutation-checked: removing the §4.3 attributes, and making the relationship
unendable, each turn it red and name which condition failed.

1. **`conformance:orcs` criterion 1 extended to assert ORCS §4.3 field presence** — all ten
   attributes, `type`, `purpose`, `status` and `validity` among them. Today the criterion
   asserts only that one record exists per person, that a peer's credential is attributed to
   the peer, and that an unlisted issuer is refused, so it cannot see this gap and reports PASS
   regardless. Until it is extended, criterion 1 passing says nothing about §4.3.
2. **A smoke assertion that a residency can be ended**, and that an ended residency is not
   silently re-issued by `issue()` returning `exists`.
3. **An invariant test that no decision path reads `type` or `purpose`**, mirroring the origin
   invariant in `src/core/proofing/residence.ts`. Amendment 1 is only worth making if the
   prohibition is enforced; a recorded-but-unread field with nothing checking it will be read
   eventually.
4. **A test that nothing lapses on its own** — a record whose validity end has passed is still
   `ACTIVE` until someone ends it. This is the assertion that keeps Amendment 2 true after
   somebody later adds a retention sweep.