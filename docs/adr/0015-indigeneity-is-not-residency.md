# 15. Indigeneity is not residency, and the register holds no origin

- Status: Accepted — records behaviour the code has had since the first Nigerian adapter, now asserted by project acceptance criterion 14
- Date: 2026-10-06
- Relates to: [0004](0004-one-deployment-one-jurisdiction.md), [0011](0011-residency-anchor-is-a-jurisdiction-choice.md)

## Context

Nigeria has two answers to "where is this person from", and they are different facts with
different consequences.

**Residence** is where a person lives. The Constitution gives every citizen the right to move
freely throughout Nigeria and to reside in any part of it (s.41), and forbids disability "merely
by reason of the circumstances of his birth" (s.42). State residents' registration laws, such as
Kaduna's of 2021 and Lagos's of 2011, register residence: a person who has lived in the state for
a stated period, or intends to, with a verified national identity.

**Indigeneity** is where a person's parents or grandparents came from. The Constitution defines
"belong to" a state by reference to a parent or grandparent who "was a member of a community
indigenous to that state" (s.318(1)). In practice a local government's certificate of origin or
"indigene letter" is what gates state civil-service posts, places and fees at state
universities, state scholarships, federal character quotas, and in many places the purchase of
land and the holding of political office. The certificates have no national standard, are issued
at the discretion of local officials, and have been documented for sale. Two attempts to let
long residence confer the rights of origin failed in the National Assembly, the second withdrawn
in July 2025 after organised opposition. Human Rights Watch documented, in Kaduna among other
places, officials refusing certificates to long-settled residents of one faith while issuing
them to recent arrivals of another.

The national identity record carries **both** fields: a residence state and a self-declared
origin state. A residency register that read the origin field could do one of two harmful
things with it. It could use origin as evidence of residence, which would register a person
where their grandparents lived rather than where they live, and refuse the person who moved. Or
it could store origin beside residence, which would turn a register of who lives where into the
instrument communities have feared since the Jos North elections were suspended over it: a list
of who is a settler.

## Options considered

1. **Store origin, never use it.** Rejected. A column that is never read is a column that will
   be read: by an export, by a reporting query, by a future feature with a good reason. Data
   minimisation under the Nigeria Data Protection Act 2023 asks why it is held at all, and there
   is no answer.
2. **Use origin as weak residence evidence**, on the theory that most people live where they
   are from. Rejected. The people this register most needs to include are exactly the ones for
   whom that is false: the person who moved for work, the displaced family in a host community,
   the pastoralist whose grandparents' community is three states away.
3. **Capture origin from the national record, map it to a distinct field, and never let it
   reach the residence evaluation, the record, or the credential.** Chosen. The adapter sees it
   because the national record returns it; the register does not keep it.

## Decision

**The register holds no origin field, in any form.** Not on the resident record, not in the
credential subject, not in a column, not in the statistics projection. The Nigerian adapter maps
the national record's residence state and origin state to two distinct fields of the verified
identity so that they cannot be confused, and only the residence state is ever offered as
proof-of-residence evidence, as `register_declared_residence`, capped low because it is
self-declared to the national register and coarse.

**Origin never proves residence.** A foundational record whose origin state matches the claimed
unit while its residence state names another unit is refused for want of residence proof, under
every policy that requires proof. The reverse issues.

**The credential states residence and nothing about belonging.** It says this jurisdiction
holds a residency record for a person whose identity was verified against a named source, at a
stated assurance level, by a stated method. The README says in plain words what it does not
prove, and indigeneship is first on that list.

**This is not a position on Nigeria's indigeneity debate.** Whether residence should confer the
rights of origin is a constitutional question for Nigerians and their legislatures. This record
only ensures the register cannot be used to settle it by other means, in either direction.

## Consequences

- The `originAdminUnit` field exists on the verified identity type and in the Nigerian adapter's
  response mapping, deliberately, so that a source which returns origin has somewhere to put it
  that is not residence. Nothing downstream reads it.
- A jurisdiction whose law genuinely requires origin for some purpose does not get it from this
  register. It gets it from the authority that issues certificates of origin, and the two
  systems are not joined here.
- Bulk export by any attribute is operator-gated and audited; the statistics export projects a
  fixed set of categorical fields that does not include, and cannot be extended to include,
  anything origin-shaped without changing the type the aggregator accepts.
- The same reasoning applies outside Nigeria to any register that could become a proxy for
  ethnicity, caste, religion or ancestry. The core carries no such field for any country.

## How this is verified

Project acceptance criterion 14 in `scripts/orcs-conformance.ts` issues against a mock
foundational record whose origin matches the claimed unit while its residence does not, and
asserts the refusal; issues the reverse and asserts success; decodes the credential and
serialises the record and asserts that neither contains a key naming origin or indigeneity; and
reads the Prisma schema and asserts the resident table has no such column. The ratchet holds it
at PASS.
