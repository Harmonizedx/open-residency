# 18. Arrival notices under a declared exclusivity rule

- Status: Accepted
- Date: 2026-10-13
- Relates to: [0004](0004-one-deployment-one-jurisdiction.md), [0007](0007-residency-status-is-lifecycle.md), [0017](0017-the-specification-is-a-working-document.md)

## Context

A deployment is one subnational government, and a person's residencies elsewhere reach it as
credentials to verify, never as rows ([ADR-0004](0004-one-deployment-one-jurisdiction.md)).
That settles multiplicity. It leaves one question open: what happens when a person who holds
this jurisdiction's residency registers with another one, and the two are not meant to
coexist. The project's specification calls this a conflict, says concurrent relationships are
not conflicts in themselves, and asks for a declared exclusivity rule. Until now nothing
implemented one: two deployments could both hold a person ACTIVE indefinitely, and the
acceptance criterion that asserts the rule had reported FAIL since the suite was written.

The standards review of October 2026 found the statutory pattern that fits. Under Germany's
registration law (BMG §33), the authority that registers a mover notifies the one the mover
came from, within three working days, electronically, and that notice drives deregistration
at the old address. No shared register, no central adjudicator: a message between peers,
and a local decision. The review's first design had the new jurisdiction write the ending
into the old register directly, which is exactly the cross-register authority ADR-0004 rules
out; this record replaces that design.

## Options considered

1. **A central conflict service** that sees every registration and tells each deployment
   what to do. Rejected. It is a national registry of movements by another name: it
   concentrates the correlation risk pairwise identifiers exist to prevent, needs a national
   owner no software decision can supply, and asserts authority over state registers that
   no Nigerian body holds.

2. **The new jurisdiction ends the old relationship**, by calling the old deployment's
   lifecycle route with its own credentials. Rejected. One register writing to another is the
   non-goal in the project's own terms, and it makes the stronger action the only one: a
   jurisdiction that wants to be told, and decide for itself, has no way to say so.

3. **A signed notice, and a rule declared by the receiving deployment.** Chosen. The new
   jurisdiction tells the old one what it saw; what the old one does about it is its own
   declared policy for that peer. Nothing crosses a register boundary except a statement
   the sender can be held to.

## Decision

**When a person presents a federated peer's residency credential at this deployment's desk
and is registered here, this deployment sends the peer a signed arrival notice. When this
deployment receives such a notice from a peer, its declared rule for that peer decides what
happens, locally.**

The notice is a JWT, `typ: arrival-notice+jwt`, signed with the sending deployment's issuer
key, issued by its issuer DID and addressed to the receiving deployment's issuer DID. It
carries the presented credential's identifier, a SHA-256 of the credential exactly as
presented, when it was presented and when the person was registered, and the registered
claims that make it a JWT. **It carries nothing about the person.** The receiving deployment
already holds every personal fact the notice could name; naming them would add disclosure
and no information. A notice carrying any claim outside that set is refused, so a peer that
starts adding a name to its notices is refused rather than quietly accommodated.

A notice is heard only from a peer in the federation trust list, signed by a key the list
holds for that peer, addressed to this deployment, within its validity, and never seen
before. It is stored as received, so anyone holding the peer's public key can verify later
what was said.

The rule is one of four, declared per peer in the trust list, with a grace period in days:

| Rule | On receipt | After the grace period |
| --- | --- | --- |
| `none` | the notice is noted; no conflict exists | nothing |
| `record` | a conflict is opened for a person | nothing |
| `suspend` | a conflict is opened, pending | the relationship is SUSPENDED |
| `end` | a conflict is opened, pending | the relationship is ENDED |

The default for a peer that declares nothing is `record` with three days. The rule is per
peer because reciprocity is bilateral: it is what the two jurisdictions agreed, and a
deployment may well tell one neighbour and act on another's word. It is this deployment's
rule, not the sender's: a peer cannot choose what happens in a register that is not its own.

A transition the rule makes goes through the ordinary relationship lifecycle
([ADR-0007](0007-residency-status-is-lifecycle.md)), attributed to the rule and the peer,
with the notice named in the reason. It does not touch the credential: ending a residency
and revoking its credential remain two acts, and the second is an operator's call through
the existing routes. A person can resolve a conflict at any point: reversing a pending
notice cancels it, reversing a suspension reinstates the relationship, and an ended
relationship cannot be reversed from here, because ENDED is terminal and the person
re-enrols. That irreversibility is why the grace period exists, and why `end` without one
should be a deliberate choice.

Both directions are stored: what this deployment sent, with whether it arrived, and what it
received, with what the rule did. An undeliverable notice is kept and retried on a sweep; a
peer being unreachable is an ordinary operating condition, not a reason to lose the record.

What this decision does not do: it does not decide which residency is the right one. That
is a question for a person, under the jurisdiction's own law, with the notice as evidence.

## Consequences

- Two deployments can no longer both hold a person ACTIVE without the first knowing, when
  the two are federated and the second sends notices. A deployment that is not told, or
  declares `none`, keeps the posture it had.
- The trust list gains two per-peer fields: `arrivalNoticeUrl`, where the peer receives
  notices, and `exclusivity`, the rule and grace period for notices from that peer. A list
  entry without them behaves as before, except that notices from that peer are recorded
  under the default rule.
- A deployment exposes one public route, for peers. It is rate-limited like every public
  route, and a request that is not a validly signed notice from a listed peer is refused
  before anything is read from the register.
- The operator surface gains the notice listing, the sending route, the resolution route
  and a sweep. The sweep also runs on a timer where peers are configured.
- Acceptance criterion 2 asserts the behaviour on two in-memory deployments: no conflict
  under `none`, a recorded and attributed conflict under `record`, a reversible pending
  state and a rule-applied suspension under `suspend`, and the refusals. Its baseline verdict
  moves from FAIL to PASS in the same change.
- Criterion 2's "serves" line names the BMG §33 pattern, ADR-0004 and this record. No
  external framework asks a subnational register to adjudicate conflicts; what is external
  is the pattern of notice-driven deregistration between peers.

## How this is verified

- `npm run smoke:arrival-notice`: two deployments, every rule, the grace period, reversal,
  reinstatement, the refusals, and delivery failure with retry.
- `npm run acceptance`, criterion 2, as described above, with the baseline at PASS.
- `npm run test:store-e2e`: the notice store on a real PostgreSQL, both directions, the due
  query and the failed-outbound query.
- The end-to-end job drives the HTTP routes against the real application: a peer's notice
  accepted and acted on, an unsigned one refused, the operator routes guarded.
