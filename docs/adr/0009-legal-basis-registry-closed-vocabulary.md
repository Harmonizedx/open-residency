# 9. The Legal Basis Registry is a closed vocabulary, and consent is refused without one

- Status: Accepted — lands in the same change as the implementation it describes, so this file
  exists on `main` only once the change has landed.
- Date: 2026-08-17
- Relates to: [ADR-0003](0003-orcs-normative-orra-advisory.md),
  [ADR-0008](0008-assurance-registry-maps-existing-vocabularies.md)

## Context

ORCS §9 requires a consent grant to capture *"subject, controller, processor, purpose, data
categories, scope, expiry and evidence of agreement"*, and requires the deployment to
*"resolve every `legalBasisReference` through the Legal Basis Registry"*.

The record held four of those eight: subject, purpose, scope and expiry. Those four describe
what the **relying party** receives. The four that were missing — controller, processor, data
categories, evidence of agreement — are the ones that say who is **accountable** for it, and
none of them existed. A citizen inspecting their own consents could see that Health had read
their residence claim, and could not see which body was the controller, under what authority,
or on what evidence they were taken to have agreed.

Those are the first questions a data-protection regulator asks, and they were exactly the
questions the register could not answer.

§9 also requires replacement to *"preserve the previous record and create a new version"*.
Re-granting with different scopes left the old record `'active'` beside the new one, so a
resident could hold two live consents for one relying party with no statement of which
superseded which — and the revocation path would find only one of them.

## Options considered

1. **Add the four fields as optional columns.** Rejected. An optional accountability field is
   one that arrives empty: the SSO consent step would have passed nothing, every grant would
   have carried blanks, and the register would satisfy §9's field list while answering none of
   §9's questions. This is the same failure the credential lifecycle rejected for revocation
   metadata — the difference between a requirement and a field is whether the write is refused
   without it.
2. **Record `legalBasisReference` as a free-text string.** Rejected on §9's own wording, and
   for the reason [ADR-0008](0008-assurance-registry-maps-existing-vocabularies.md) gives about
   assurance: a reference nobody can look up documents nothing. `legalBasisReference: "the law"`
   is not a citation.
3. **Ship a full set of legal bases as platform defaults.** Rejected. A lawful basis is a
   citation to a specific statute book. Shipping a "public task" entry for Katsina or Nairobi
   would put a claim about their law into their config file, which is the guess-wearing-a-
   version-number that ADR-0008 refuses to make about assurance authorities.
4. **A closed registry, seeded with consent alone, extended per jurisdiction.** Chosen.

## Decision

**Consent is refused when it cannot be recorded accountably, and every legal basis resolves
through a closed registry.**

Concretely:

- The ORCS §9 fields are **required**. `grant()` returns `{ ok: false, reason }` rather than
  writing a record when the controller is unnamed, the data categories are empty, the evidence
  of agreement has no retention reference, or its timestamp will not parse.
- `legalBasisReference` resolves through `LegalBasisRegistry` or the grant is refused.
  `UNKNOWN_LEGAL_BASIS` and `LEGAL_BASIS_NOT_IN_FORCE` are distinct outcomes, because "you
  cited something that does not exist" and "you cited something that was repealed" call for
  different corrections.
- The registry ships **one** basis: `orcs:legal-basis:consent`. Consent is a lawful basis in
  each regime the vocabulary is drawn from (NDPA 2023 s.25(1)(a), GDPR Art.6(1)(a), Convention
  108+ Art.5(2)), so shipping it asserts nothing about anybody's local law. Every other basis
  is declared by the deployment in `dataProtection.legalBases`.
- **`resolve` and `get` are deliberately different reads.** `resolve` answers "may processing
  proceed on this basis, now" and refuses a deactivated or out-of-window entry. `get` returns
  the record whatever its state, because a consent granted under a since-repealed by-law must
  stay followable — deactivating a basis must not retroactively blank the history citing it.
- Deactivation requires a reason and an authority, and there is **no reactivation**. A basis
  relied on again after withdrawal is a new entry with its own version, so the gap during which
  processing was not authorised stays visible rather than being closed over.
- Replacement versions the record: the new grant is `version + 1` with `supersedesId`, and the
  previous becomes `'replaced'` with `supersededById`. Exactly one consent per relying party is
  live at a time.

### The expiry exception is load-bearing

§9 says expiry must *"prevent further processing automatically, **unless another valid legal
basis applies**"*. That exception is the whole reason the basis is recorded separately from the
consent status, and it turns on the **kind** of basis rather than on one being present:

- a consent-based grant dies with the consent — withdrawal stops processing at once;
- a statute-based grant survives it — a citizen withdrawing consent does not repeal a by-law;
- withdrawing the **basis itself** stops the statute-based grant too.

Treating any resolvable basis as sufficient would let a withdrawn consent keep authorising the
read, which is the failure §9 is written to prevent.

### The record is enforced on the release path, not merely stored

§9 requires expiry to *"prevent further processing automatically"*, and a rule enforced nowhere
is not a rule. Claim release therefore consults the consent record: `claims()` resolves the
governing consent for the relying party and calls `mayProcess` before returning anything beyond
`sub`.

Refusal **degrades to `sub` alone** rather than failing the request. The relying party already
holds the pairwise subject identifier, so returning it discloses nothing further, and
authentication keeps working while the personal data stops flowing — withdrawing consent and
being locked out of the login are different things. Already-issued ID tokens cannot be recalled;
this takes effect on every userinfo read and every subsequent token, and `POST /consent/:id/revoke`
additionally destroys the OIDC grant for immediate session termination.

This was not the first implementation. The first recorded consent state and read it nowhere on
the release path, so a withdrawn consent kept releasing the full claim set for the life of its
tokens — and the conformance criterion was flipped to PASS on assertions made directly against
the domain object. That is precisely the "capability exists but no code path exercises it end to
end" case this repo's rules say must stay PARTIAL.

### Which bases exist is config; which are withdrawn is state

The registry is rebuilt from configuration at every boot, so a withdrawal held only in memory
would be undone by the next restart, and in a multi-instance deployment only the process that
served the request would stop honouring the basis. Withdrawals are persisted and replayed at
boot. **Only** withdrawals: persisting the definitions too would create a second source of truth
able to disagree with the config file a reviewer actually reads.

## Consequences

- The `grant()` contract changed from returning `{ record, receipt }` to a discriminated
  outcome. Every call site was updated; the SSO consent step now **fails the interaction**
  rather than finishing it, because releasing claims on a consent the register declined to
  write is the exact gap this closes.
- The controller is a deployment fact, declared once in `dataProtection.controller` rather than
  passed per grant. It falls back to `credential.issuerName` — defensible, since the body
  issuing the credential is processing the data to do it, but not always right where an agency
  issues on a state's behalf. Deployments SHOULD name it.
- Rows written before this migration read as having no accountability fields, which is what
  they were. They are **not** backfilled: inventing a controller and a lawful basis for a grant
  nobody recorded one for would manufacture the evidence this change exists to require.
- ORCS §9's `CONSENT.WITHDRAWN` event still has nowhere to go until the event registry exists
  (G-04). Withdrawal is recorded and enforced; it is not published.

## How this is verified

- `npm run smoke:consent` — 47 assertions, most of them refusals: the required fields, the
  closed vocabulary, the effective window, duplicate registration, deactivation attribution,
  the replacement chain, and the expiry exception in both directions.
- `npm run smoke:sso-oidc` — the enforcement, through the **real** oidc-provider: the same
  bearer token is replayed after withdrawal and no longer releases the residency claim, while
  `sub` still resolves so authentication is unaffected. Asserting this against the domain object
  alone is what let the gap exist in the first place.
- `npm run conformance:orcs` — criterion 4 asserts all eight §9 grant attributes, that an
  unregistered reference is refused rather than stored, that a repealed basis stays readable
  while no longer resolving, and that withdrawing a basis stops the grants relying on it.
  Criterion 4 was PARTIAL [G-09]; it is now PASS.