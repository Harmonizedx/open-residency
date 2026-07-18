# DPG Registry submission pack

This is a ready-to-paste answer set for submitting OpenResidency to the Digital Public
Goods Registry (digitalpublicgoods.net). Fill the bracketed deployment specifics before
submitting.

## Project basics

- Name: OpenResidency
- Owner / submitting organization: HarmonizedX Limited (RC 2011004, Abuja, Nigeria)
- Website / repository: [https://github.com/harmonizedx/openresidency]  (confirm org handle)
- License: Apache-2.0
- Sector: Digital identity, digital public infrastructure
- Type: Software

## Short description

Country-agnostic, open-source subnational Residency ID and single sign-on platform. It
binds any national foundational ID (NIN, Aadhaar, Huduma, and others via config) to a
W3C Verifiable Credential, works offline for low-connectivity areas, and provides
cross-sector SSO, consent, and a tamper-evident audit trail. Reusable by any state,
province, or county.

## The nine indicators

1. **Relevance to SDGs.** Primary: SDG 16.9 (legal identity for all). Secondary: SDG 1,
   3, 10 through inclusive access to health, tax, permits, and subsidy services.
   Evidence: `README.md`, `docs/ARCHITECTURE.md`.

2. **Open license.** Apache-2.0. Evidence: `LICENSE`, `NOTICE`.

3. **Clear ownership.** HarmonizedX Limited. Evidence: `NOTICE`, `GOVERNANCE.md`.

4. **Platform independence.** No mandatory closed dependency. Node.js runtime;
   PostgreSQL behind a swappable `ResidencyStore` port; framework-agnostic core.
   Evidence: `src/core/*`, `src/core/residency/ports.ts`.

5. **Documentation.** README, architecture, API reference, OpenAPI 3.1 spec, SDK docs,
   deployment guide, and a runnable smoke test. Evidence: `README.md`, `docs/`,
   `docs/openapi.yaml`, `scripts/smoke.ts`.

6. **Non-PII data / open data by design.** Raw national IDs are never stored; only a
   tokenized subjectRef is persisted. Published artifacts (DID document, status list)
   contain no personal data. Evidence: `prisma/schema.prisma`, `src/core/foundational/*`.

7. **Privacy and applicable laws.** Data minimization, per-client OIDC consent, national
   ID never shared with relying parties, first-class revocable consent with receipts.
   Deployer completes a DPIA against local law (for example the Nigeria Data Protection
   Act). Evidence: `src/core/consent/*`, `docs/DPG.md`.

8. **Standards and best practices.** W3C Verifiable Credentials, DID, Bitstring Status
   List, OpenID Connect / OAuth 2.0, EdDSA/Ed25519. Secrets via env/KMS, HMAC
   tokenization, short-lived tokens, rate limiting, tamper-evident audit log. Evidence:
   `src/core/credentials/*`, `src/sso/*`, `docs/API.md`.

9. **Do no harm by design.** Exclusion risk mitigated by offline and USSD paths;
   over-collection mitigated by minimization; issuer-key compromise mitigated by KMS
   custody and revocation; audit tampering detectable via the hash chain. Known
   limitations are stated openly. Evidence: `README.md` caveats, `SECURITY.md`,
   `src/core/audit/*`.

## Do-no-harm detail (the reviewer will ask)

- Data privacy and security: see indicators 6, 7, 8 and `SECURITY.md`.
- Inappropriate/illegal content: not applicable (infrastructure, no user content).
- Protection from harassment: not applicable (no social features).
- Note the honest caveats: the dev issuer key is ephemeral (production supplies one from
  an HSM/KMS), OTP delivery is a logging stub pending an SMS/USSD aggregator, and
  proof-of-residence is a policy input the system records but does not adjudicate. A
  production deployer addresses these; they are documented rather than hidden.

## Attachments to reference in the submission

- Repository URL (public)
- `LICENSE`, `NOTICE`, `GOVERNANCE.md`, `SECURITY.md`, `CONTRIBUTING.md`
- `README.md`, `docs/openapi.yaml`, `docs/DPG.md`
