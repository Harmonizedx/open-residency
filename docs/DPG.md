# Digital Public Good alignment

This is the single source of truth for OpenResidency's DPG Standard alignment: the mapping to
the nine indicators, the evidence for each, the honest gaps, and the registry submission pack.
It is written to be candid about what is in place today and what an adopting team must
complete; where an indicator is not yet fully met, it says so rather than reframing the
question.

One document on purpose. Registry answers kept separately from the indicator mapping drift
apart, and a reviewer reads both.

## Open standards used

- **W3C Verifiable Credentials** for the residency credential (VC-JWT profile).
- **W3C Decentralized Identifiers** (`did:web` for government issuers, `did:key` for fully
  offline verification).
- **W3C Bitstring Status List** for cacheable, offline-checkable revocation.
- **OpenID Connect / OAuth 2.0** for cross-sector single sign-on.
- **OpenID4VCI / OpenID4VP** for wallet-based issuance and presentation.
- **EdDSA / Ed25519** for compact signatures suitable for QR and paper carriage.

Building on these open standards is deliberate: it keeps OpenResidency interoperable with any
conformant wallet, verifier, or relying party, and avoids a proprietary lock-in that would
disqualify it as a DPG.

## The nine DPG Standard indicators

### 1. Relevance to Sustainable Development Goals

Primary: **SDG 16.9** (legal identity for all). Secondary: **SDGs 1, 3 and 10** through
inclusive access to health, tax, permits and subsidy services. Residency credentials unlock
service access for subnational populations who hold a national ID but have no verifiable
relationship with the jurisdiction that actually serves them.

Evidence: `README.md`, `docs/ARCHITECTURE.md`.

### 2. Use of an approved open licence

Apache-2.0, an OSI-approved licence. Evidence: `LICENSE`, `NOTICE`.

### 3. Clear ownership

Owned and stewarded by HarmonizedX Limited (RC 2011004, Abuja, Nigeria). Copyright is recorded
in `NOTICE`; ownership and maintainership in `GOVERNANCE.md`.

### 4. Platform independence

No mandatory closed-source dependency. Runtime is Node.js; PostgreSQL sits behind a swappable
`ResidencyStore` port; the core domain logic has no framework dependency and runs unchanged in
the hermetic CI suites and against a real database.

Evidence: `src/core/*`, `src/core/residency/ports.ts`, `src/prisma/prisma.service.ts`.

### 5. Documentation

README (architecture, quickstart, onboarding), an architecture document, an API reference, an
OpenAPI 3.1 specification served by the running app, SDK and integration guides, a deployment
guide, and runnable smoke tests that double as executable documentation.

Evidence: `README.md`, `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/openapi.yaml`,
`docs/SDK.md`, `docs/INTEGRATION.md`, `docs/DEPLOY.md`, `scripts/smoke.ts`.

### 6. Mechanism for extracting data

The Standard asks for a documented way to extract or import **non-PII** data in a
non-proprietary format. OpenResidency provides four, none of which carries personal data:

- **Aggregate residency statistics.** `GET /admin/statistics` (JSON) and
  `GET /admin/statistics.csv` (RFC 4180 CSV) return counts by country, subnational unit,
  provider, assurance level, and provisional status. The aggregator consumes a projection type
  with no name, date-of-birth, gender, contact, `residentId` or `subjectRef` field on it, so
  the absence of personal data is a property of the types rather than of reviewer diligence.
  Small cells are suppressed (see below).
- **Published trust artifacts.** The issuer DID document (`GET /.well-known/did.json`) and the
  Bitstring Status List (`GET /.well-known/status/{cc}.json`) are public JSON/JSON-LD by
  design, and contain no personal data — revocation is an index into a bitstring, not a name.
- **Schema and vocabulary.** The OpenAPI 3.1 specification (`GET /openapi.yaml`) and the
  residency JSON-LD context (`GET /contexts/residency/v1`) are open, machine-readable, and
  what the Interoperability SDK is generated against.
- **Configuration import.** Jurisdictions are defined by YAML config (`config/countries/*.yaml`)
  and reference datasets by CSV (`config/datasets/*.csv`). Both are non-proprietary and are the
  supported way to load non-PII reference data into a deployment.

Statistical disclosure control is applied to the aggregate export because "aggregate" is not
automatically "anonymous": a ward with one resident in it is re-identifiable by anyone who
knows the neighbourhood. Cells below `STATISTICS_SUPPRESSION_THRESHOLD` (default 5) are
withheld; if exactly one cell would be withheld, the smallest survivor is withheld with it, as
a single gap beside a truthful total is a subtraction away from being no gap at all; and a
grand total below the threshold is withheld for the same reason. This is disclosure control,
not a proof — correlating releases over time can still narrow a cell, and a public release
deserves its own disclosure review.

Resident-level records are **not** part of this surface. `GET /admin/residents` returns
pseudonymous identifiers, which remain personal data, and is governed as such: operator
authentication, the `support` role, and an audit record of who read the register.

Evidence: `src/core/statistics/aggregate.ts`, `src/admin/statistics.controller.ts`,
`scripts/statistics-smoke.ts` (gated in CI), `docs/API.md`, `docs/openapi.yaml`.

### 7. Adherence to privacy and applicable laws

Against the six privacy requirements the DPGA added to the Standard in 2024:

| Requirement | Status |
| --- | --- |
| Data minimisation | **Met.** Raw national IDs are never stored; only an HMAC-tokenised `subjectRef` is persisted. The national ID is never shared with relying parties. Phone numbers are stored encrypted, off the residency port, so the core service cannot reach them. |
| User consent mechanisms | **Met.** First-class, revocable consent records with signed, portable receipts, plus per-client OIDC consent. |
| Data usage transparency | **Partial.** Consent flows and processing are documented in the API reference and architecture docs; there is no standalone data-protection statement yet. |
| Privacy by design (PII deletion) | **Not met.** There is no erasure endpoint today. See the gap note below. |
| Data retention transparency | **Not met.** No retention policy or automated purge exists today. |
| Data governance and access controls | **Met.** Role-scoped operator identity with per-operator API keys and rotation, replacing a shared admin key; privileged reads are audited to a named operator; the audit log is a tamper-evident hash chain. |

**Known gap.** PII erasure and retention are not implemented. They are not a documentation
task: the audit log is a hash chain, so "delete the resident" and "keep the chain verifiable"
have to be reconciled deliberately (tombstone the payload, retain the hash) rather than by
adding a `DELETE` route. Until that lands, this indicator is partially met, and saying otherwise
in a submission would be an over-claim a reviewer can check in ten minutes.

A DPIA assesses a deployment processing real people's data; this repository is software and
processes none. The adopter completes the DPIA and the records of processing against their
governing law — for a Nigerian deployment, the Nigeria Data Protection Act — and confirms the
identity authority's usage terms permit the binding.

Evidence: `src/core/consent/*`, `src/core/foundational/*`, `src/core/audit/*`,
`src/core/operator/*`, `src/core/messaging/contact-directory.ts`.

### 8. Adherence to standards and best practices

The open standards listed above, plus: secrets via environment or KMS, HSM/KMS issuer-key
custody with no exportable private key, HMAC tokenisation, short-lived tokens, in-application
and ingress rate limiting, a tamper-evident audit log, and fail-closed biometric verification.

CI gates every merge on a typecheck, W3C conformance (VC Data Model 2.0, Bitstring Status List,
Data Integrity), an Inji Draft-13 profile conformance suite, OpenID4VCI and OpenID4VP flows
including the attacks they must reject, SSO login factors, WebAuthn, cross-issuer federation,
operator identity and roles, issuer-key custody against PKCS#11 HSM and AWS/Google Cloud KMS,
the non-PII statistics export, a full-stack run of the real application against PostgreSQL, and
a container build.

Secure development: Dependabot covers the application, the SDK and the GitHub Actions
themselves; CodeQL runs `security-and-quality` on every pull request and weekly; a CycloneDX
SBOM is generated from the installed tree and published as a build artifact.

**Stated plainly:** the dependency audit gate is set at *critical* on runtime dependencies,
not *high*. The tree does not pass at `high` today — `undici` (via `jsonld`), `lodash` (via
`@nestjs/config`), and `multer` with `@nestjs/platform-express` carry high-severity
advisories, and every available fix is a semver-major upgrade. Those upgrades are tracked and
must land before a production deployment; `jsonld` in particular affects JSON-LD context
processing, so it cannot be bumped without re-running the full credential conformance suite. A
gate set where it currently holds, with the debt reported on every run, is more honest than
one set where it would fail on the first build and be disabled by the following week.

Evidence: `src/core/credentials/*`, `src/sso/*`, `.github/workflows/ci.yml`,
`.github/workflows/codeql.yml`, `.github/dependabot.yml`, `SECURITY.md`, `docs/INTEROP.md`.

### 9. Do no harm by design

- **Exclusion.** Mitigated by offline verification (QR carriage, cached status lists) and a
  USSD state machine for feature phones with no data plan. Evidence: `src/core/offline/*`,
  `src/offline/offline.controller.ts`.
- **Over-collection.** Mitigated by minimisation and tokenisation; see indicator 7.
- **Issuer-key compromise.** Mitigated by HSM/KMS custody and revocation via the status list.
- **Audit tampering.** Detectable via the hash chain; `GET /audit/verify` confirms integrity.
- **Re-identification from published statistics.** Mitigated by the suppression described in
  indicator 6.
- **Privileged insider access.** Mitigated by per-operator identity, roles, and audited reads.

The system has no user-generated content and no social features, so the content-moderation and
harassment provisions of the Standard do not apply.

## Honest caveats

Stated openly rather than hidden, because a reviewer will find them:

- The development issuer key is ephemeral; production supplies one from an HSM or KMS.
- SMS/USSD delivery is stubbed at the gateway boundary — the state machine and webhook are
  real, the aggregator integration is the deployer's.
- Proof of residence is a policy input the system records and levels, but does not adjudicate.
- PII erasure and retention are not implemented (indicator 7).

## What an adopter completes before production

- Issuer key custody in an HSM or KMS.
- The national ID API contract and legal basis with the identity authority.
- A data protection impact assessment and records of processing under local law.
- Gateway integration for USSD/SMS delivery.
- A disclosure review before publishing the statistics export as open data.

## Reuse beyond one country

Nothing in the core is Nigeria-specific. The same binary serves multiple jurisdictions at once
(one config file each), which makes OpenResidency suitable as shared regional infrastructure
rather than a single-country fork.

---

# Registry submission pack

What to put in the DPG Registry form at digitalpublicgoods.net. The indicator answers are the
nine sections above — paste from there rather than rewriting them here.

## Project basics

- Name: OpenResidency
- Owner / submitting organization: HarmonizedX Limited (RC 2011004, Abuja, Nigeria)
- Repository: https://github.com/Harmonizedx/open-residency *(must be public at submission time)*
- License: Apache-2.0
- Sector: Digital identity, digital public infrastructure
- Type: Software

## Short description

Open-source subnational trust infrastructure that lets governments establish, manage and
exchange verified, purpose-scoped jurisdictional relationships between residents and their
jurisdictions — giving citizens inclusive, privacy-preserving access to public services. It
binds any national foundational ID (NIN, Aadhaar, Huduma, and others via config) to a W3C
Verifiable Credential, works offline for low-connectivity areas, and records consent and a
tamper-evident audit trail. Reusable by any state, province, or county.

## Do-no-harm questions the reviewer will ask

The Standard's do-no-harm prompts map onto indicator 9 above, with two the form asks
separately:

- **Inappropriate or illegal content:** not applicable — infrastructure, no user-generated
  content.
- **Protection from harassment:** not applicable — no social features.

Repeat the "Honest caveats" section verbatim in the submission rather than smoothing it over.

## Two indicators need a decision before submitting

Indicators 7 and 8 are recorded above as incomplete. The form should not say otherwise:

- **Indicator 7.** PII erasure and retention are not implemented. Either land them first, or
  submit with the gap stated plainly and a timeline. Do not answer the deletion and retention
  questions as though the capability exists.
- **Indicator 8.** No dependency scanning, SBOM, or static analysis in CI yet. Cheap to add;
  better added than explained.

## Attachments to reference

- Repository URL (public)
- `LICENSE`, `NOTICE`, `GOVERNANCE.md`, `SECURITY.md`, `CONTRIBUTING.md`
- `README.md`, `docs/DPG.md`, `docs/openapi.yaml`

## Pre-submission checklist

- [ ] Repository is public.
- [x] `CODE_OF_CONDUCT.md` exists (Contributor Covenant 2.1, with project-specific rules on
      real personal data and on exclusionary proposals).
- [ ] Data-protection statement and retention policy published.
- [ ] PII erasure implemented, or the gap stated with a timeline.
- [x] Dependency scanning, SBOM, and static analysis in CI (Dependabot, CycloneDX SBOM,
      CodeQL). Note the audit gate sits at *critical* pending four semver-major upgrades —
      see indicator 8.
- [x] No dead documentation links. Indicator 5 is a documentation indicator, and a broken link
      in the README's front-door table is the first thing a reviewer clicks. Every `docs/` link
      in the repository now resolves.
- [ ] This document re-read end to end, so every claim still matches the code.
