# 17. The specification is a working document, not a published standard

- Status: Accepted
- Date: 2026-10-13
- Relates to: [0003](0003-orcs-normative-orra-advisory.md), [0004](0004-one-deployment-one-jurisdiction.md)

## Context

Two documents govern this codebase: a core specification, which [ADR-0003](0003-orcs-normative-orra-advisory.md)
made normative for how the code is judged, and a reference architecture, which it made
advisory. Both were written by this project in August 2026. Neither is published: they are
circulated as working documents, and their text is not in this repository.

A standards review in October 2026 asked whether that arrangement was honest in public. It
found that the repository's public surface still presented the specification as if it were
something a reader could check against. The script that asserts the specification's nine
acceptance criteria was named `conformance:orcs`; its output was headed with the
specification's section number and cited further sections beside each verdict; the signed
release asset was called a conformance record; the API documentation cited sections by number.
A reviewer testing the README against the running software, as a Digital Public Good evaluator
will, would meet the word "conformance" attached to a document they cannot open. The README's
prose had already been corrected to say the criteria are the project's own and that no external
conformance is claimed for them. The names and the output had not.

Two things follow. One is a decision this project had deferred: publish the specification text,
or not. The other is what the suite and the public documents should call themselves once that is
decided.

## Options considered

1. **Publish the specification text.** Rename it to a profile and interoperability
   specification, adopt RFC 2119 language, version it, add a changelog and governance rules for
   how a change to it is judged. Rejected for now. Publishing creates a maintenance and
   governance obligation, and nobody outside the project has asked to implement from the text.
   The Digital Public Goods Alliance does not evaluate standards, so publication earns nothing
   there. The adopter this project is preparing for needs the acceptance suite, the decision
   records and the API documentation, not a specification. The option is not closed; the
   trigger that reopens it is stated below.

2. **Keep the text private and keep the "conformance" naming.** Rejected. "Conformance" is a
   claim that a third party can verify. Attached to a document only the project can read, it is
   a claim nobody can verify, and the review was right to call it unverifiable.

3. **Keep the text private and name the suite for what it is: the project's acceptance
   criteria.** Chosen.

## Decision

The specification text is a working document and stays unpublished. [ADR-0003](0003-orcs-normative-orra-advisory.md)
continues to govern how the code is judged inside this repository: the specification remains
the internal contract, and a deviation from it is still a finding. "Normative" is a word for
inside the repository.

From this change:

- The suite that asserts the specification's nine criteria, and the five project criteria added
  beside them, is the project's **acceptance suite**: `npm run acceptance`, implemented in
  `scripts/acceptance-criteria.ts`, ratcheted against `scripts/acceptance-baseline.json`, with
  `ACCEPTANCE_UPDATE_BASELINE=1` to record an improvement. `npm run conformance:orcs` remains as
  an alias for one minor release and is then removed.
- The suite's output is headed "Acceptance criteria". It prints, beside each verdict, the
  external requirement the criterion serves; it does not cite sections of the working document.
  Where a criterion serves nothing external, it says so, and that is a finding about the
  criterion.
- The signed release asset is `ACCEPTANCE-CRITERIA.txt`, and the release-notes section is
  headed "Acceptance criteria".
- Public material — the README, the DPG evidence, the API documentation, the SDK readme, the
  OpenAPI description, release notes — refers to the document only as the project's own
  specification, cites decision records rather than its sections, and uses "conformance" only
  for suites that verify against standards other people wrote: `npm run test:conformance` for
  the W3C and OpenID suites and `npm run conformance:mosip` for the MOSIP integration gate.
- Decision records and source comments may still cite the document by section. They are
  reasoning for a maintainer who has the document, not claims to a reader who does not, and
  rewriting them would change nothing a reader of the public surface sees.

**Revisit when** a second implementer wants to build from the text, a peer jurisdiction asks
to verify this deployment against something it can read, or a standards body offers to host the
document. Any of those makes option 1 worth its cost, and the rename to a profile and
interoperability specification happens then, with the governance that goes with it.

## Consequences

- The acceptance suite's two tallies, their ratchet and the CI job that runs it are unchanged.
  Only names and printed text move. The required status check keeps its name, because the job
  also runs the external conformance suites.
- A reader of the public surface can no longer be led to believe the software conforms to a
  standard called by the specification's name. What they can check is what the README says:
  that each acceptance criterion names the external requirement it serves, and that CI holds
  every verdict at its baseline.
- The two findings the suite still reports as not met (criterion 2, the exclusivity rule;
  criterion 8, the event envelope) stay as they are. Naming the suite honestly does not change
  what it measures.

## How this is verified

- `npm run acceptance` prints a report headed `== Acceptance criteria ==` and a summary line
  beginning `== Specification criteria:`; CI runs it as the ratchet.
- `npm run conformance:orcs` runs the same suite, for one minor release.
- A search of the README, `docs/DPG.md`, `docs/API.md`, `docs/openapi.yaml`, `sdk/README.md`,
  `CHANGELOG.md` and the release workflow for the specification's identifier or for section
  citations of it finds none outside the changelog's history of earlier releases.
