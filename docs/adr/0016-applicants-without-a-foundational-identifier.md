# 16. Applicants without a foundational identifier

- Status: Proposed — a decision for the maintainers; the code today does what section "What the
  code does today" says, and project acceptance criterion 10 reports PARTIAL until this is decided
- Date: 2026-10-06
- Relates to: [0004](0004-one-deployment-one-jurisdiction.md), [0010](0010-authentication-refs-are-not-residency-identities.md), [0014](0014-identity-links-are-a-record-not-a-column.md)

## Context

This register is foundational-first. A residency record is keyed on a tokenised reference to an
identifier the national identity source holds, and issuance begins by verifying the applicant
against that source. ORCS defines a Person as "a subject represented by an internal identifier
and one or more verified external identity bindings", and the one-deployment-one-jurisdiction
model (ADR-0004) relies on that reference being unique per person.

The people this design excludes are not a rounding error. The World Bank's status report on
Nigeria's identity programme, from August 2026, puts enrolment at 134.6 million and issued
identifiers at 117.5 million at the end of June 2026, against a target of 180 million; women are
40.4 million issued against a target of 79 million; children under sixteen 26.3 million against
60.8 million. Under-five birth registration fell to 39.7 percent in the 2024 demographic survey.
A 2025 report from Niger State counted 21 enrolment centres for 7.5 million people, with a
round trip costing more than a week's household income. The people without an identifier are disproportionately
women, children, the rural poor, the displaced, and the stateless at the borders. They are also
the people a residency register exists to include, and ID4D's first two principles, universal
access and the removal of barriers, are about exactly them.

Kaduna's own law does not help here: it requires a national identifier, with a Kaduna address on
it, before a residents' card is issued. A register that strictly follows the state's law
reproduces the national programme's exclusion profile.

## What the code does today

An applicant whose identifier does not verify is refused. The refusal is recorded with a
reference the person can quote, the machine-readable reason, the deciding operator or ruleset,
and the jurisdiction's appeal path, and an operator can review it. That is a decision, and it is
appealable, which is more than most registers offer. It is not a route to a residency record.

Two things that look like routes are not. The **provisional** record exists for a foundational
source that is temporarily unreachable, not for a person the source does not know: it is
reconciled against the live source later and revoked if the reconciliation fails. The
**identity-link registry** (ADR-0014) manages which identifiers belong to which person; it does
not create a person who has none.

## Options

1. **Hold the line: no foundational identifier, no record.** Honest about what the register is.
   Keeps ORCS's Person definition and ADR-0004's uniqueness intact. Reproduces the national
   exclusion profile and gives the register nothing to say about the people it turned away
   except a refusal count.

2. **An attested-only residency record and credential**, keyed on something other than a
   foundational reference: a register-issued identifier, with the person's identity established
   by community attestation and the enrolment desk's own comparison. Includes everyone. But it
   breaks the thing that makes the register trustworthy: two desks could enrol the same person
   twice with no way to notice; the credential would assert an identity the register itself
   established, which ORCS §1.2 and this project's own positioning say it does not do; and
   downstream relying parties could not distinguish a verified holder from an attested one
   unless the credential said so, in which case it becomes a marker of the unverified.

3. **A counted referral with a reserved place.** The register records the application as a
   refusal of a distinct class, `NO_FOUNDATIONAL_IDENTITY`, with the appeal path pointing at the
   nearest enrolment centre of the foundational source; it keeps the residence evidence the
   applicant brought, so that when the identifier arrives the application is completed rather
   than restarted; and it reports the count of such referrals, by unit, as a first-class
   inclusion metric beside enrolments and deliveries. No credential is issued and no person
   record is created until the identifier exists. The register cannot include the person yet,
   but it can see them, hold their evidence, and tell the programme how many it is failing.

4. **Option 3, plus a jurisdiction-declared attested path for named classes of person**, such
   as children under a registered guardian, or people in a displacement camp under a camp
   manager's attestation, issuing a credential that states its binding method as attestation
   and carries a reduced validity. Includes the most excluded classes without pretending the
   binding is something it is not. The relying party sees the binding method, as it already does
   for every credential, and the jurisdiction decides which services accept it.

## Proposed decision

**Adopt option 3 now; make option 4 a jurisdiction's declaration, off by default, and build it
when a jurisdiction asks.**

Option 3 costs little, breaks nothing, and gives the register the one thing it most lacks on
this subject: numbers. The refusal class and the retained evidence are additive to the existing
refusal record; the referral count is one more cell in the statistics export; the appeal path is
the configured one with the enrolment centre added.

Option 4 is the real inclusion step and is a policy decision each jurisdiction must take in its
own law, because it decides what the state's credential certifies. The code should make it
possible to declare, exactly as the residence anchor (ADR-0011) and the residence modes are
declared, and should refuse to issue an attested-only credential for a jurisdiction that has not
declared the class. The credential it produces must state `applicantBinding.method` as it
already does, so that nothing is hidden from a relying party, and must not carry any field that
exists only for attested holders, so that it does not become a marker of them.

Option 2 is rejected. Option 1 is what exists, and is what the register falls back to when a
jurisdiction declares nothing.

## Consequences if adopted

- A new refusal reason class and a retained-evidence field on the refusal record; a referral
  count in the statistics export; the enrolment centre in the appeal path. All additive.
- Project acceptance criterion 10 moves from PARTIAL to PASS when the referral is recorded with
  its evidence and counted, and gains a second half when option 4 is built: an attested-only
  issuance for a declared class succeeds, and the same request for an undeclared class is
  refused by name.
- The README's "verify residents against their national ID" gains the sentence that follows
  from this: an applicant without one is referred and counted, not lost, and a jurisdiction may
  declare classes it will register on attestation.
- Nothing in ORCS's Person definition changes under option 3. Option 4 would need ORCS §3 to
  admit a Person whose only binding is an attestation, which is a change to the project's own
  specification and should be made there when the first jurisdiction declares the class.

## How this would be verified

Criterion 10 today asserts the refusal is recorded with a reference, a reason and the appeal
path. Under option 3 it additionally asserts the reason class, the retained evidence, and the
referral count. Under option 4 it asserts a declared-class issuance succeeds with the binding
method stated and no attested-only field present, and an undeclared-class request is refused.
