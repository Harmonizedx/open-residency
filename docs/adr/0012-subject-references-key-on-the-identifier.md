# 12. A subject reference keys on the identifier, not the route

- Status: Accepted — the implementation lands in the same change as this record.
- Date: 2026-08-21
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md), [ADR-0010](0010-authentication-refs-are-not-residency-identities.md)
- Supersedes: the namespacing half of [ADR-0010](0010-authentication-refs-are-not-residency-identities.md)

## Context

`subjectRef` is `HMAC(pepper, "<namespace>:<identifier>")`, and the namespace was the
**provider code**. So the same person, holding the same national identifier, produced different
references depending on which software handed the number over:

```
same person, same NIN, same deployment:
  desk / NIN gateway : ng_nin:3565d2a9c60f50813554beb466e3bbc1b7a0261f
  online / eSignet   : oidc:c6d7bd1f02dfc4ab16fd6afef63404498ae344e7
  reconcile?         : NO — two unmergeable records
```

Nothing about the person changed. The identifier arrived through a different door.

For an agency running both an enrolment desk network and an online channel -- which is the
common shape, and KADRIMA's -- that generates duplicates by design. They are unmergeable:
the reference is one-way, and no identity-link lifecycle exists to correct a mapping
(finding G-05). The register would need reconciling by hand, forever, for a reason it created
itself.

### Why ADR-0010 chose the provider, and why that reason has expired

[ADR-0010](0010-authentication-refs-are-not-residency-identities.md) namespaced by provider
while defending against something real: an OIDC `sub` is pairwise per relying party, so a
record keyed on one is unmatchable by anything outside that relationship. That reasoning is
correct and this record does not disturb it.

But the OIDC foundational adapter (#136) solves that problem better and at the source: it
refuses to construct a foundational identity from a pairwise `sub` at all, returning
`NO_AUTHORITATIVE_IDENTIFIER` rather than falling back. Once an adapter can *only* emit an
authoritative identifier, namespacing by provider is no longer doing the work it was introduced
for. What remains of it is accidental coupling to the route.

## Options considered

1. **Keep the provider namespace and reconcile by hand later.** Rejected: the correction tool
   does not exist (G-05), and every record written meanwhile is one more to reconcile.
2. **Drop the namespace entirely.** Rejected: it exists for a real reason. A NIN and an Aadhaar
   number are both digit strings, and without separation the same digits from two national
   schemes would hash to one reference for two different people.
3. **Namespace by the identifier's type, declared by the provider.** Chosen.

## Decision

**A provider MAY declare `identifierType` -- `NIN`, `AADHAAR`, `HUDUMA` -- and subject
references are namespaced by that rather than by the provider code.**

- Two providers declaring the same type share a namespace, so two routes to the same national
  identifier produce one reference and one record.
- Different types stay separate, preserving the collision protection the namespace exists for.
- **Omitted, the namespace falls back to the provider code.** This is additive: no reference
  already written changes value, and a deployment that declares nothing behaves exactly as it
  did.

An empty or whitespace `identifierType` is refused at config load rather than silently ignored,
because a declaration that reads as present and behaves as absent is the worse of both.

### What this does NOT do

It does not merge existing records. A deployment that has already written references under two
provider namespaces still holds two rows per person; this stops new ones being created, and the
merge needs G-05. Declaring `identifierType` on an existing deployment changes the namespace for
records written *after* it, which is a migration and must be treated as one.

## Why

**The namespace's purpose is a property of the identifier.** Preventing an Aadhaar number
colliding with a NIN is about the two schemes, not about the software that transmitted them.
Keying on the route conflated those and charged the cost to the resident.

**The route is already recorded elsewhere.** `providerCode` sits on every record, so which
source established an identity remains auditable without being load-bearing for identity.

**Additive by construction.** The fallback is what makes this safe to land before any
deployment exists, and it is why this is a default change rather than a data migration.

## Consequences

**Good.** Desk and online enrolment reconcile. Provider migration stops being destructive: a
jurisdiction moving from a NIN gateway to an OIDC register keeps every record, because the NIN
did not change. One fewer invariant an operator has to know.

**Bad.** Two providers declaring the same type are asserted to be talking about the same
identifier space, and nothing verifies that claim -- a deployment declaring `NIN` on a source
that actually returns something else would merge two people. That is a configuration error with
a serious outcome, and only the jurisdiction can know the truth of it.

**Open.** Nothing validates identifier shape per type. A `NIN` type could carry a per-type
pattern so a mismatched source is caught at enrolment rather than trusted; that is worth doing
and is not done here.

## How this is verified

`npm run smoke:identifier-namespace` -- 13 assertions, in `npm test`:

- Two and three routes declaring `NIN` produce identical references; the namespace is `nin:`,
  not the provider.
- `NIN` and `AADHAAR` differ **on identical digits** -- the collision protection still holds.
- A provider declaring nothing produces exactly the byte-identical reference it did before, and
  an empty declaration falls back rather than creating an empty namespace.
- The deployment pepper still isolates deployments.
- Config accepts the declaration, permits its absence, and refuses an empty one.
