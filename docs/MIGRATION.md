# Migrating an existing register

Most jurisdictions that adopt this will already have a register: a residents' agency with
years of enrolments, a card scheme, a database behind an enrolment desk. The question is never
"how do we start from zero" but "how do we carry what we have without carrying its faults".
This guide is the runbook for that. It uses only paths the software has today, says what each
migrated row will and will not be able to claim, and is honest about the one thing the current
code cannot do.

## What a migrated record is

A record issued here says: *this jurisdiction holds a residency record for a person whose
identity was verified against a named source, at a stated assurance level, by a stated method,
with residence established by stated evidence.* A migrated record must say the same, truthfully,
about data that was gathered under another system's rules. So every migrated row carries
**provenance**: which register it came from, which record in it, when that register enrolled the
person, and that the residence evidence is the old register's word rather than fresh. Nothing
in a migrated record pretends the old register's checks were this system's checks.

## The shape of the work

1. **Export the old register** to a flat extract: one row per person, with at least the national
   identifier (or whatever foundational identifier the old register keyed on), the demographic
   fields it holds, the residence unit it recorded, the date it first enrolled the person, and
   the old record's own identifier. Leave out what this register will not hold: photographs,
   biometric templates, and any origin or indigeneity field. Those stay in the old system or are
   destroyed under the old system's retention rules; they do not cross.

2. **Decide the identity source.** Two options.

   - *The national identity authority, live.* Each migrated person is verified against the
     authority at migration time. Slow, and it needs the authority's verification service, but
     every migrated row then carries a current verification rather than a historical one. This
     is the option for a register whose old checks were weak.
   - *The old register as an imported source.* The extract itself is configured as the
     foundational source (`foundational.provider: IMPORT`, see `config/countries/xf-import.yaml`).
     A match establishes that a record existed in the old register, which is what it is: the
     software caps the assurance of an imported source below a live one, and the credential says
     so. This is the option when the old register's identity checks were as good as the
     authority's or the authority cannot be reached at scale. The two can be combined: import
     now, re-verify live over time, and the record's assurance rises when it happens.

3. **Carry the old residence as evidence, not as fact.** For each row, the issuance request
   carries one `residenceEvidence` entry of method `authority_attestation` with `attesterType:
   registrar`, `reportedUnit` set to the unit the old register recorded, `since` set to the old
   enrolment date, and `ref` set to the old record's identifier. That is a registrar vouching that
   the old register held this residence from that date. Under the jurisdiction's residence rule
   the `since` date is what a minimum-duration test measures, so a person enrolled years ago in
   the old register is not asked to prove six months again.

4. **Declare the policy for migration explicitly.** Run the migration under a configuration whose
   residence policy accepts `authority_attestation` from `registrar`, and whose `methodCeiling`
   caps it at the level the jurisdiction is willing to grant on the old register's word: RAL1 if
   the old checks were thin, RAL2 if they were a desk officer's. Record that configuration's
   version; it is what every migrated row's `policyVersion` will name.

5. **Issue through the SDK, row by row.** There is no bulk-import endpoint, deliberately: every
   row goes through the same gates a fresh applicant does, so a migrated person cannot end up
   with a record the rules would have refused. The SDK's `issueResidency` in a loop, with the
   operator identity of the migration run as `decidedBy`, is the path. Expect refusals, and keep
   them: each is recorded with a reference and a reason, and the refusal list at the end is the
   list of people the old register held who do not satisfy the new rules. That list is a finding
   about the old register, and the agency decides what to do with it.

6. **Do not activate on issue.** Set `credential.activateOn: first_delivery` for the migration.
   Every migrated credential is then ISSUED and not ACTIVE until the person has actually been
   given it, by whatever channel the agency uses, and the delivery counts show how many of the
   migrated population have been reached. A migrated register whose credentials all read ACTIVE
   on day one has learned nothing from the programmes that stalled on exactly this.

7. **Keep the old identifier reachable.** The old record's id is in the evidence `ref` and in the
   audit trail of the issuance. A person who turns up with an old card can be found by it through
   the audit log, and the agency's own crosswalk, kept outside this system, maps old to new.

## What a migrated row cannot claim

- **Owner binding.** The old register's enrolment desk may have compared the person to a
  document, or may not. Unless the agency can vouch for it per row, migrated rows carry
  `applicantBinding.method: none`, and the credential says so. The jurisdiction's policy must
  therefore allow issuance without binding for the migration run, or every row is refused; a
  subsequent in-person step upgrades the binding when the person collects.
- **A fresh residence check.** The evidence is the old register's word, dated to the old
  enrolment, capped at the configured ceiling. A verifier reading the credential sees that.
- **Children without an identifier.** The pipeline is foundational-first. A child in the old
  register without a national identifier cannot be migrated as a residency record today; see
  ADR-0016 for the proposed referral path, and count them.
- **Biometrics.** They do not cross. If the old register's card scheme depends on them, that
  scheme keeps them, and this register holds the credential.

## Order of operations

Config and policy for the migration run → dry run against a sample with issuance refused on any
unexpected reason → the impact assessment updated for migration as a processing activity →
migration run → refusal review → delivery campaign → re-verification against the live authority
over time → retire the migration configuration and restore the jurisdiction's ordinary policy.

## Numbers to watch

Issued; refused by reason; delivered by channel; collected; re-verified live. The statistics
report gives the counts; the refusal references give the people.
