# 11. What residency is anchored to is a jurisdiction's choice

- Status: Accepted — the implementation lands in the same change as this record.
- Date: 2026-08-20
- Relates to: [ADR-0003](0003-orcs-normative-orra-advisory.md), [ADR-0004](0004-one-deployment-one-jurisdiction.md)

## Context

Residence proof here was defined as administrative-unit matching. Evidence reconciles to a unit,
`unitMatchRequired` demands it equal the claimed unit, and `RAL0..RAL3` grades how strongly.
There was no address anywhere in the model.

That is what residency means in Nigeria, and across much of Africa and South Asia, where a great
deal of housing has no formal street address. It is a good model for those places, and the
absence of addresses is a real privacy benefit: a residency register holding physical locations
for millions of people is a stalking tool and a far more attractive breach than one that does
not.

**It is not what residency means everywhere.**

- **Germany.** The Bundesmeldegesetz makes address registration compulsory: every resident must
  register their address within fourteen days of moving, and that registration gates a residence
  permit, a bank account and benefits.
- **Japan.** The jūminhyō certifies a current residential address, and is what unlocks municipal
  services and school enrolment.
- **The Nordics.** Continuously updated address-level population registers, to the point they
  have largely displaced the census.

In those jurisdictions "which state do you live in" is not a lighter-weight residency. It is not
residency. A system that cannot hold an address cannot express their concept at all.

### Why this was invisible

ORCS §15 criterion 9 asserts that the core contains no Nigeria-specific hard-coded field names
or hierarchy assumptions, and it passes honestly: no Nigerian identifier, threshold or document
type is embedded anywhere.

But a system can contain no Nigerian *names* and still be Nigeria-shaped in its *concepts*. The
criterion tests for hard-coded identifiers; it cannot see a hard-coded model. That is a category
of failure §15 was not built to detect, and it is worth stating plainly for the next one: a
green criterion 9 means the core is free of one jurisdiction's vocabulary, not free of its
assumptions.

## Options considered

1. **Leave the unit model as the only one.** Rejected: it makes the software unusable in a large
   part of the world while the project describes itself as global public infrastructure.
2. **Make address the model, with unit derived from it.** Rejected: it inverts the exclusion.
   Requiring an address shuts out informal settlements and rural wards -- exactly the people a
   residency register exists to reach -- and imposes address normalisation on jurisdictions that
   have no addresses to normalise.
3. **Support both, as a jurisdiction declaration.** Chosen.

## Decision

**A jurisdiction declares what its residency is anchored to: `unit` or `address`.**

- `unit` is the default. Every existing deployment and configuration keeps its exact current
  meaning, and no jurisdiction that does not want addresses ever handles one.
- `address` requires the evidence to name the address the applicant claims, **in addition to**
  the unit still agreeing. Address anchoring is strictly stronger than unit anchoring, never a
  substitute: a German municipality still has to establish that the address is in its own
  municipality, and an address alone does not say that.
- Where an address is held it is **destroyed by erasure**, alongside the name. An erasure that
  removed who somebody is and kept where they live would be worse than none.

### The core does not parse addresses

Lines are stored as the jurisdiction records them and compared through a deliberately naive
normalisation -- case, punctuation and whitespace, nothing else. `12 Ahmadu Bello Way` and
`12 Ahmadu Bello Wy` are different addresses to this code.

Resolving that abbreviation is a judgement about one country's conventions, and a core serving
every country has no business making it. A deployment needing gazetteer-grade matching
normalises before it reaches here. Imposing a single address shape would re-commit the exact
error this record corrects, pointing the other way.

An informal descriptor -- *"third compound past the borehole, Rigasa ward"* -- is a first-class
address. For some residents it is the only locator that exists, and a register refusing it would
exclude them while claiming to be about inclusion.

## Why

**The pattern already exists in this codebase.** The foundational identity source is an adapter
chosen by configuration. Assurance values resolve through a governed registry with per-provider
mappings. Who decides an enrolment is derived from the methods a jurisdiction accepts. Anchoring
is the same kind of thing, and was the one such choice still hard-coded.

**The privacy argument survives, scoped correctly.** Not holding addresses is genuinely safer,
and remains the default. What changes is that it stops being imposed on jurisdictions whose law
makes the address the registered fact. The protections travel with it: minimised, erased,
absent from the credential unless a deployment puts it there.

**ORCS §4.4 does not compel either reading.** It states that households and addresses are
separate entities and that a person MAY have several -- descriptive, with no MUST. So this is a
design choice rather than a conformance repair, and is recorded as one.

## Consequences

**Good.** The software becomes usable where residency is address registration. Unit-anchored
deployments are untouched. The assumption is now visible in configuration rather than implied by
the absence of a field.

**Bad.** A second anchoring mode is a second path to test and to reason about, and address
matching is naive by design, which will surprise somebody expecting fuzzy matching.

**Open.** Household remains unmodelled (G-12). Social registries use it for targeting worldwide
and its definition is deeply jurisdictional -- who heads a household, how polygamous households
are represented. It should be the same kind of declared capability, and it should not be built
speculatively: getting the model wrong encodes one culture's assumption about families into who
receives a benefit.

## How this is verified

`npm run smoke:address-anchor` -- 21 assertions, in `npm test`. It holds three things:

1. **Unit anchoring is unchanged.** Evidence with no address still satisfies a unit-anchored
   policy end to end.
2. **Address anchoring is stricter, not merely different.** The same unit-only evidence stops
   satisfying it; evidence for a different address does not satisfy it; the unit must still
   agree, so a correct address in the wrong municipality fails.
3. **Erasure destroys the address.** Asserted against both stores.

The Prisma path was additionally round-tripped against a live PostgreSQL, because a missing
schema column typechecked silently -- Prisma's `data` object is spread into the call, which
skips excess-property checking, so the column's absence surfaced only when the migration was
generated and came back empty. The in-memory store passed throughout. That is the failure mode
worth remembering: a smoke suite on an in-memory store cannot see a persistence bug.