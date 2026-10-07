# Roadmap

What is planned, what triggers it, and what is deliberately not planned. Dated so a reader can
tell a stale entry from a current one. The acceptance suite (`npm run conformance:orcs`) is the
authoritative statement of what is done; this page is the statement of what is next.

Updated 2026-10-06.

## Planned, in order

| Item | Trigger or dependency | Status |
| --- | --- | --- |
| Interfaces in the languages people use, starting with Hausa for the first Nigerian deployment: the USSD menu, the enrolment interface, the resident self-service pages | the first deployment's language list | not started |
| Offline enrolment with later synchronisation: a desk that loses connectivity continues enrolling and reconciles when it returns | a deployment with intermittent connectivity at enrolment points | partly present: provisional issuance exists; a queued, resumable enrolment client does not |
| A referral path for applicants without a foundational identifier, with the applicant's evidence kept and the referral counted | decision on ADR-0016 | proposed |
| Conflict detection under an explicit, per-peer exclusivity rule, evaluated over a signed arrival notice from a peer jurisdiction | an ADR and a second deployment to notify | designed; §15 criterion 2 fails until built |
| A GovStack Digital Registries self-assessment with a thin data adapter and a filed fit-gap | none; next engineering slot | not started |
| SD-JWT VC issuance with Token Status List and ES256, alongside the existing JSON-LD and JWT formats | a named wallet for a named adopter needs selective disclosure of the name and date-of-birth block, or an eIDAS-style verifier appears | deferred |
| Certificate chains on issued credentials and an ETSI TS 119 602 trust-list import, then export | a second peer jurisdiction, or a national root certificate authority issuing a subordinate | deferred |
| A postcode adapter for Nigeria's digital postcode: validate structure offline, derive the state, refuse on disagreement, never raise assurance | the postcode's identity linkage ships, or a deployment asks | deferred |
| Ingest from a state social register with provenance flags | a format specification in hand | deferred |
| Passkey as a self-service factor for the access log | a deployment asks; enrolment and sign-in already exist | not started |

## Decisions pending

- Whether to publish the project's own specification text openly with change governance, or keep
  it as internal documentation. Until decided, the public position is that the acceptance suite is
  the project's own and no external conformance is claimed for it.
- Whether to build an event architecture or amend the specification to make the audit chain the
  record (§15 criterion 8).
- ADR-0016.

## Not planned

- A card. The credential is the record; cards, printed QR codes, paper and USSD are carriers a
  deployment may use or not.
- Any origin, indigeneity, ethnicity or ancestry field (ADR-0015).
- A national or multi-jurisdiction register. A deployment is one jurisdiction (ADR-0004).
- mdoc issuance, until an African deployment or verifier needs proximity presentation.
- Direct registration in the EU trust ecosystem; verification-side compatibility through an
  ETSI-shaped trust list is the reachable goal.

## Known interoperability caveat

The MOSIP Inji wallet's documentation lists W3C Verifiable Credentials Data Model 1.1 for
JSON-LD credentials, with 2.0 named for SVG rendering. This project issues under the 2.0 context.
The conformance checks here run against reference implementations and published behaviour, not a
live Inji instance, so whether a current Inji wallet accepts a 2.0-context JSON-LD credential is
unverified by this project. A deployment targeting Inji should confirm it against the wallet
version it will ship with before promising wallet carriage, and should raise an issue here with
the result either way. See `docs/INTEROP.md`.
