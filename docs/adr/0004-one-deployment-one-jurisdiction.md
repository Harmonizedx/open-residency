# 4. One deployment, one jurisdiction: multiplicity lives in the ecosystem

- Status: Accepted
- Date: 2026-08-03
- Relates to: [ADR-0003](0003-orcs-normative-orra-advisory.md)

## Context

ORCS §1 is emphatic that residency is "not a single boolean attribute and not an exclusive
claim by one government", and §4.4 gives the worked example: one person with a family home in
Katsina, employment in Kano and study in Lagos — three concurrent, compatible, purpose-scoped
relationships.

There are two ways to build that, and they are not compatible.

**Centralised.** One database holds all of a person's relationships. `subjectRef` is not
unique; a composite key over (person, provider, jurisdiction, purpose) permits many rows per
person. One instance can answer "where is this person resident?" across every jurisdiction.

**Federated.** Each subnational government runs its own deployment. Katsina's instance holds
Katsina relationships and nothing else. The person's Kano relationship exists in Kano's
deployment and reaches Katsina as a *verifiable credential*, not as a row. No instance holds
all three; the ecosystem does.

The centralised design was implemented first (commit `1937c6a`) and this ADR reverses it.

## Options considered

1. **Centralised** — drop `subjectRef @unique`, key on (person, provider, jurisdiction,
   purpose). Rejected: a subnational instance holding another jurisdiction's relationships
   asserts authority ORCS §1.2 explicitly denies it, concentrates correlation risk that
   pairwise subject identifiers exist to prevent, and needs a national owner that no software
   decision can supply.
2. **Hybrid** — local relationships authoritative, peers cached as read-only rows. Rejected:
   a cached row is indistinguishable from an authoritative one at the point of use, which is
   how a convenience cache becomes a shadow national registry.
3. **Federated** — one deployment per jurisdiction, peers reached by credential verification.
   Chosen. The primitives already ship and are tested (`npm run smoke:federation`).

## Decision

**A deployment is one subnational government. `subjectRef` is unique within it: one person,
one residency record, here. ORCS §4.4 multiplicity is satisfied across deployments, through
credential verification and the federation trust list — never by one instance holding another
jurisdiction's relationships.**

Consequences for the model:

- `subjectRef @unique` stays. The duplicate-enrolment guard is a feature, not the limitation
  it first appears to be.
- `relationshipType`, `purposeCode` and `status` were introduced by the centralised design and
  have been **removed with it**. A record in this deployment *is* this jurisdiction's residency;
  there is no second kind for the type to distinguish, so carrying the ORCS §6.1 vocabulary here
  would describe a multiplicity that cannot exist. The §6.2 lifecycle is deliberately deferred
  rather than deleted on principle — it becomes meaningful when relationship *lifecycle*
  endpoints exist (submit, review, suspend, reinstate), and should return then as a considered
  addition, not as a leftover of the reversed design.
- Cross-jurisdiction awareness is a *verification* capability (`src/core/credentials/federation.ts`),
  not a storage one.

## Why

**A subnational deployment asserting authority over other jurisdictions is the thing ORCS
prohibits.** A Katsina instance holding a Kano employment relationship is claiming to be a
register of record for Kano. ORCS §1.2 lists exactly this as a non-goal: OpenResidency "is not
a national identity authority" and does not require "every jurisdiction to use one central
database".

**It matches how governments actually procure and operate.** Each state owns its instance, its
keys, its data and its policies. A shared national table would need a national owner, which is
a political fact no software decision can supply.

**Data protection improves.** A breach of Katsina's deployment exposes Katsina residents, not a
national picture of everyone's movements between states. The centralised design would have
concentrated exactly the correlation risk that pairwise subject identifiers exist to prevent.

**The federation primitives already exist and are tested.** Cross-issuer trust, peer DID
resolution and credential verification ship today (`npm run smoke:federation`).

## Consequences

**Good.** Sovereignty per jurisdiction. Smaller blast radius. No national-registry politics.
The duplicate guard is simple and enforceable at the database level.

**Bad.** No single query answers "all of this person's relationships" — by design. A citizen-
facing view of everything they hold must be assembled from credentials in their wallet, not
from a server-side join. Conflict detection (ORCS §7, G-06) becomes a cross-deployment problem
rather than a single-table one, and will need the event and exchange layers (G-04) before it
can be built.

**Also.** One person can hold only one relationship *per deployment*. A person who both lives
and works in Katsina is one record there, undifferentiated. If a jurisdiction needs
to distinguish those, that is a future change to this decision — record it as a superseding
ADR, not as a quiet relaxation of the unique constraint.

## How this is verified

`npm run conformance:orcs` criterion 1 asserts the federated reading directly:

- (a) a deployment issues exactly one residency per person, and re-enrolment is idempotent
      rather than duplicating;
- (b) a peer jurisdiction's credential verifies here and is attributed to the peer rather than
      absorbed as if locally issued.

An earlier version of that check asserted one store holding three relationships for one
person. That was measuring a national registry, and it passing would have been the defect.
