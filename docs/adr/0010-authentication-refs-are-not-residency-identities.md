# 10. An authentication reference is not a residency identity

- Status: Accepted
- Date: 2026-08-17
- Relates to: [0004](0004-one-deployment-one-jurisdiction.md), [0006](0006-additive-migration-resident-facade.md)

## Context

Issue #116 asked which namespace an eSignet-derived identity should use for `subjectRef`:
the `oidc_`-prefixed one the upstream client derives, or a `FoundationalProvider`-namespaced
one. It framed this as a choice with a wrong answer that would "make records unmatchable
later".

The framing does not survive contact with the two identifiers involved.

`UpstreamOidcClient` derives its reference from the OP's `sub`, under a provider code hashed
from the OP's issuer URL. That `sub` is **pairwise per relying party** — eSignet issues a
different one to every RP, deliberately, so that two services cannot correlate the same
person. A foundational adapter derives its reference from the authoritative identifier the
register is keyed on: a NIN, an Aadhaar number, whatever the jurisdiction's source of truth
uses.

These are different inputs. `HMAC(pepper, "oidc_ab12:<pairwise sub>")` and
`HMAC(pepper, "ng_nin:<NIN>")` cannot be made equal by choosing a different prefix, because
the prefix is not what differs — the thing being hashed is. No namespacing decision
reconciles them.

So the question is not which namespace to use. It is what each reference is *for*.

## Decision

**A residency record's `subjectRef` is always derived from the foundational provider's
authoritative identifier, namespaced by that provider's code.** A deployment declares exactly
one `foundational.provider`, so within a deployment there is one namespace and the `@unique`
constraint means what ADR-0004 says it means: one person, one residency, here.

**An upstream OIDC reference is an authentication artifact and is never stored as a residency
identity.** It answers "is this the same browser-session subject as last time, at this OP?"
It cannot answer "is this the same person the register already holds?", because a pairwise
subject is by construction unlinkable to anything outside the relationship that issued it.

To stop the two being confused by anyone reading the types, the field on `UpstreamIdentity`
is named `authenticationRef`, not `subjectRef`. The previous name invited exactly the
substitution this record forbids, and a comment saying "do not use this as a subjectRef" is
weaker than not offering a field that looks like one.

**Consequently, an eSignet foundational adapter (#116) must key on an authoritative
identifier eSignet returns** — a national identifier surfaced through `claimMapping` — and
must refuse to construct a foundational identity from a pairwise `sub` alone. An adapter that
tokenized the pairwise subject would produce a reference that changes when the deployment
re-registers as an RP, and that no other channel enrolling the same person could reproduce.
That is the failure #116 was worried about, arriving by a different route than it expected.

## Consequences

- The upstream sign-in flow keeps doing what it does today: it yields an `ApplicantBinding`
  of `authoritative_authentication` for a registrar to present to `POST /residency/issue`.
  It contributes proof that the person was present; it does not contribute the identity.
- A jurisdiction wanting eSignet to be *both* its authenticator and its foundational source
  needs eSignet to release a national identifier, not only a pairwise subject. Whether it
  does is a property of that deployment's eSignet configuration and its legal basis for
  releasing the identifier — not something this codebase can decide.
- If a future OP offers no authoritative identifier, it can still be an authenticator. It
  simply cannot be the register's source of identity, and the deployment pairs it with one
  that is.
- Erasure is unaffected: `erase()` replaces the residency `subjectRef` with a tombstone, and
  no upstream reference was ever stored to leak past it.
