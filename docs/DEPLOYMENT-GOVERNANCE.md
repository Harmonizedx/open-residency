# Governing a deployment

This document answers the questions a government asks before it runs this software, and the
questions an evaluator asks before it recommends that a government should. They are the
questions the UN's Universal DPI Safeguards Framework puts to any digital public infrastructure:
who operates and maintains it, who pays, which law authorises it, how privacy is ensured, how
remediation works, how it is secured, and how it is sustained. The software answers some of them.
Most are answered by the jurisdiction, and this document says which, and gives the shape of a
good answer where the project has one.

It is written for Nigeria first, because the first adopters are Nigerian states, and generalises
where it can. Facts about Nigeria are cited to their source; where a fact rests on a single
report it says so.

## Who operates it

**The jurisdiction does.** A deployment is a single subnational government (ADR-0004). The
operating body is whatever that government's law names: in Kaduna, the Kaduna State Residents
Identity Management Agency under the Agency's Law of 2021; in Lagos, the Lagos State Residents
Registration Agency under its Law of 2011. The software is run by, or on behalf of, that body,
on infrastructure that body controls or has contracted.

**The project does not operate anything.** It publishes software, a reference configuration,
and the acceptance suite that says what the software does. It holds no data, no keys, and no
relationship with any resident. A deployment that cannot name its operating body in law is not
ready to deploy.

## Which law authorises it

Three layers, and a deployment needs all three.

**The state's own registration law** establishes the register, names the controller, sets the
residence rule (Kaduna: six months' residence or an intention to reside; Lagos: three months),
and says which state services the record gates. The software reads the residence rule from
configuration; it does not supply one.

**The Nigeria Data Protection Act 2023 and the General Application and Implementation Directive
2025** govern the processing. Under the Directive a state agency processing personal data at any
scale is a data controller of major importance from its first two hundred data subjects, and
ministries, departments and agencies are expressly placed at the highest tier. Article 28(3)(l)
requires a data protection impact assessment, vetted by an accredited data protection officer
and filed with the Commission **before processing starts**, for "any legal instrument or policy
which requires the processing of personal data of members of the general public". A residents'
registration law is such an instrument. The templates in `docs/templates/` are a starting point
for that assessment and the record of processing; they are not a filing.

**The National Identity Management Commission Act 2026** makes the national identification
number the foundational identifier and the Commission the root certificate authority for
national public-key infrastructure. A state register sits on top of that identifier and never
beside it: the register's subject reference is a tokenised national identifier (ADR-0010,
ADR-0012), and the register mints no competing identity. Whether the Act's text speaks to state
registers directly has not been confirmed from the gazette; what is confirmed is the practice,
in which the Commission co-launched Kaduna's programme in 2018 and lists the Kaduna agency as a
verification-service client.

## Who pays

This the software cannot answer and this document will not pretend to. What the evidence from
Nigerian programmes says is that the cost that stalls a register is not the software but
operations: enrolment desks, agents, and above all getting the credential into people's hands.
Lagos's registrations ran to millions while its validated and collected records lagged years
behind, on the agency's own account, for reasons of card supply and local printing. Kaduna is
running a randomised trial on distribution precisely because that is where the money and the
failure are.

Two design choices here lower that cost and should be in any budget conversation. The credential
is digital first and card-optional: a wallet, a printed QR, a paper document, a USSD lookup and
an agent's handover are all carriers of the same record, and a deployment may issue any of them
or none. And delivery is recorded as its own event, so the programme can see, per channel, what
reached people and what did not, before it has spent on the channels that do not work.

## How privacy is ensured

The software's part, each item verifiable in the acceptance suite or the smoke tests:

- The national identifier is never stored; a keyed hash of it is. Erasure replaces that with a
  tombstone and destroys every identifying field, the address included.
- No origin or indigeneity field exists anywhere (ADR-0015). The register cannot become a list of
  who is a settler.
- Consent is a first-class record with controller, processor, purpose, data categories, evidence
  and legal basis, and an unregistered legal basis is refused rather than stored.
- Sign-in to services uses pairwise identifiers, so services cannot join records on them.
- The credential carries the minimum: unit, assurance, binding method, residence level and
  method. Not the address unless the jurisdiction anchors on addresses; never how the person
  resides or who vouched for them.
- Every operator read of a record is audited in a hash-chained log. What is not yet built, and
  the suite reports as failing, is a way for the resident to see that log themselves.

The jurisdiction's part: the impact assessment and its filing; a named data protection officer;
retention periods set in configuration, because the software deliberately ships no default and
the Directive lapses storage six months after purpose where none is set; hosting in Nigeria,
which the national cloud computing guideline approved in 2026 makes the default for government
data at its higher classifications and encourages states to adopt; and a published privacy
notice.

## How remediation works

Three routes exist in the software and each needs a human on the jurisdiction's side.

- **A refused application** is recorded with a reference, a reason, the deciding operator or
  ruleset, and the appeal path the jurisdiction configures. The Act's section 37 right to human
  review of an automated decision is met by that path only if somebody answers it.
- **A disputed identity link** restricts high-risk use of the record until an operator resolves
  it (ADR-0014).
- **A revoked or suspended credential** carries its reason, authority, timestamp and appeal path,
  and is refused if any is missing.

The appeal path is a configuration value. A deployment that leaves it unset gets a credential
that says no path has been published, which is a finding an evaluator will notice.

## How it is secured

Issuer keys live in a hardware module or cloud key service with no exportable private key.
Secrets come from the environment or a key service, never a file. The container image is built
reproducibly, scanned, signed by digest and published with build provenance and a software bill
of materials. Dependencies are audited on every change at moderate severity and the tree
currently reports none. The OpenSSF Scorecard runs weekly and publishes its result. CodeQL runs
on every change. The details and the reporting route are in `SECURITY.md`.

## Trust between states

A person's relationships live across deployments: Katsina's register holds Katsina's, and
verifies a credential Kano issued through a list of trusted issuers (`src/core/credentials/
federation.ts`). Who keeps that list, and on what authority, is the institutional question no
Nigerian precedent yet answers: there is no inter-state identity or residency agreement, and the
existing shared registers are federal programmes or utilities rather than state-to-state
arrangements.

The design this project proposes, for discussion rather than as a decision, follows the model
that has worked elsewhere: the content of the list is decided by a committee of the issuing
states, and the signature that anchors it is held by a neutral or federal party. In Nigeria that
means, in phases:

1. **Two states, a bilateral memorandum.** Each publishes its issuer metadata and status list;
   each pins the other's keys; a two-page memorandum signed by the two Attorneys-General states
   the purposes, the minimised verification, and the exit. This needs no new institution and can
   start when the second state is ready.
2. **A registrar at the Governors' Forum secretariat** compiles a signed list from members'
   self-published metadata, admission decided by a committee of participating state agencies,
   one vote each, with the Commission, the Data Protection Commission and the Forum as non-voting
   members. Admission requires the state's legal basis, its registration and impact assessment
   with the Data Protection Commission, verified identity of the agency, and passing the
   project's acceptance suite or an equivalent interoperability test.
3. **The Commission's root** cross-certifies the registrar's key, and later signs the list itself
   as the statutory root authority, with the committee's approval record embedded. Nothing about
   the credential changes between phases.

Entries are never deleted, only changed in status, so a state's withdrawal does not invalidate
the credentials its residents already hold. The Data Protection Commission and the Governors'
Forum signed a memorandum on sub-national data protection in May 2026 and have a working group,
which is the nearest existing hook for the template a committee would need.

## How it is sustained

The honest precedent in Nigeria is the health information system that all thirty-six states run:
an international implementer, donor-funded delivery indicators, and a trained in-state cadre.
No state has adopted a shared software platform on the Forum's recommendation alone, and the
Forum has never endorsed one. A state considering this software should expect to budget for a
system integrator with a Nigerian presence, training for its agency's staff, hosting in Nigeria,
and the operations above, and should ask the project for a three-year cost model before it
procures, because the state's procurement law will ask for one.

## What to ask the project

A state's technical team should ask for, and the project should be able to show, each of the
following before a pilot: the acceptance suite's output against the version to be deployed; the
privacy statement and the impact-assessment template completed for the pilot's scope; the
configuration for the state's own residence rule and unit list; the migration plan for any
existing register, with provenance flags on migrated rows; the adapter for the Commission's
verification service tested in the Commission's sandbox; and the delivery channels the pilot will
use and how each is recorded.
