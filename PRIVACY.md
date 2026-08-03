# Privacy

This document describes how the OpenResidency software processes personal data. It is a
factual description of the software's behavior, written for deployers, integrators, and
reviewers. It is **not** a legal privacy notice for any specific jurisdiction.

OpenResidency is self-hosted infrastructure. The organization that deploys it (a state,
province, or county authority, or an operator acting for one) is the **data controller**
and owns the lawful basis, the public-facing privacy notice, retention schedules, and any
Data Protection Impact Assessment for its jurisdiction. This document explains what the
software does so that a controller can write those documents accurately.

## The core fact: the raw national ID is never stored

The foundational number a citizen presents (NIN, Aadhaar, or whatever the jurisdiction's
source uses) is **never persisted and never leaves the foundational adapter**. It is used
once, in memory, to verify the person against the configured source, and is then reduced to
a non-reversible token before anything is written down.

That token, the `subjectRef`, is a keyed HMAC-SHA256 of the raw identifier under a
**deployment pepper** (`tokenizeSubject` in `src/core/foundational/util.ts`):

- It is **non-reversible** — the raw ID cannot be recovered from it.
- It is **keyed with a deployment secret** — the pepper must come from an environment
  secret or KMS in production (`SUBJECT_PEPPER`), so even a full copy of the residency
  database does not let an attacker recompute references without the pepper.
- It is **not correlatable across deployments** — the same person tokenizes to different
  references in different deployments, because each uses a different pepper.

The raw national ID is therefore never in the residency database, never in the issued
credentials, and never in the OIDC id_token. The human-facing Residency ID is a random
value with a check character; by design there is **no template that could embed the
foundational number** in a shareable identifier (`src/core/residency/resident-id.ts`).

## What personal data is processed

The exact fields depend on the jurisdiction's YAML configuration, which maps a foundational
source's response into a normalized identity. In general the platform processes:

- **The raw foundational identifier** — transiently, in memory, for verification only; never
  stored (see above).
- **The tokenized `subjectRef`** — the stored, non-reversible reference to the person.
- **Normalized identity attributes** mapped from the foundational source (for example name
  and date of birth, as configured) and residency attributes such as the subnational unit
  and assurance level, used to issue the residency credential.
- **The Residency ID** — a generated, non-sensitive public identifier.
- **A contact number**, where a deployment configures the one-time-code fallback for SSO
  sign-in (the `contactDirectory` / `messaging` configuration). Delivery is via the
  aggregator the deployer contracts.
- **Consent records** — see below.
- **Audit events** — see below.

The issued credential is a signed W3C Verifiable Credential held by the citizen (in a
wallet, QR, or on paper). It carries residency claims, not the national ID.

## Basis for processing

The lawful basis is set by the deploying controller and its jurisdiction; the software does
not assert one on its behalf. What the software provides to support a lawful, minimal basis:

- **Purpose-limited consent at the point of claim release.** When a citizen signs in to a
  sector service (Health, Tax, and so on) over SSO and residency claims are released, that
  permission is captured as a first-class, revocable `ConsentRecord` with a stated purpose
  and the specific scopes shared, not merely an ephemeral session grant
  (`src/core/consent/consent.ts`).
- **Data minimization toward relying parties.** The OIDC subject is **pairwise** — each
  relying party sees a different, stable identifier for the same citizen, so independent
  services cannot join records on it. The correlatable `resident_id` claim is released only
  to relying parties granted the `residency` scope, and the **national ID is never shared**
  with any relying party.

## Consent capture and revocation

Consent is a first-class, portable, and enforceable record:

- Each grant records the resident reference (`subjectRef`, not the raw ID), the relying
  party, the human-readable purpose, the scopes shared, and timestamps.
- Each grant produces a **signed, self-contained consent receipt** (a compact JWT) the
  citizen can keep and that anyone can verify offline against the issuer's public key.
- Consent is **revocable, and revocation is enforced, not just noted**: withdrawing a
  consent destroys the OIDC grant it authorized and revokes the tokens issued under it, so
  the relying party stops receiving claims immediately rather than at token expiry.

## Tamper-evident audit log

Privacy-affecting actions (identity verification, issuance, credential and presentation
verification, consent grant and revocation, SSO login, operator and admin actions) are
recorded in a **hash-chained, tamper-evident audit log** (`src/core/audit/audit-log.ts`).
Each event is chained to the previous one with a SHA-256 hash, so any later edit or deletion
breaks the chain and is detectable, and the chain can be re-verified end to end.

The audit log is itself designed to be privacy-preserving: it records **what** happened to
**which** residency (by Residency ID or tokenized `subjectRef`), and never the raw national
ID or one-time codes.

## Retention

Retention schedules are owned and configured by the deploying controller; the software does
not impose a fixed retention period. Two properties are relevant to any retention policy:

- The **raw national ID is never retained** at all — it is discarded after verification.
- Consent records support a lifecycle (active, revoked, expired) and revocation, so a
  controller can honor withdrawal of consent and expiry.

The audit log is an append-only integrity record; deleting entries breaks the hash chain by
design. A controller's retention and archival policy for the audit log should account for
that property.

## Deployer responsibilities

Because this is self-hosted infrastructure, the deployer is responsible for supplying a
strong `SUBJECT_PEPPER` from a secret store, custody of the issuer key, a real SSO
authentication factor, transport and network security, database security, a public privacy
notice, and a Data Protection Impact Assessment for its jurisdiction. See
[`SECURITY.md`](SECURITY.md), the caveats in [`README.md`](README.md), and
[`docs/DEPLOY.md`](docs/DEPLOY.md).

## Regulatory alignment

The design intent — data minimization by tokenizing the national ID, purpose-limited and
revocable consent, and a tamper-evident audit trail — is meant to help a deployer meet its
data-protection obligations, including alignment with the Nigeria Data Protection Act 2023
(NDPA) for Nigerian deployments. **This document is not a legal compliance statement.** Any
formal statement of NDPA-2023 (or other regime) compliance is owned by the deploying
controller and its legal counsel.

## Reporting a privacy or security concern

Report suspected data-handling or security issues through the process in
[`SECURITY.md`](SECURITY.md). Please do not include real national ID numbers or other
personal data in a report.
