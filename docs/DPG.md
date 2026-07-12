# Digital Public Good alignment

This document maps OpenResidency to the DPG Standard so the project can be submitted to the DPG Registry. It is written to be honest about what is in place today and what an adopting team must complete.

## Open standards used

- **W3C Verifiable Credentials** for the residency credential (VC-JWT profile).
- **W3C Decentralized Identifiers** (`did:web` for government issuers, `did:key` for fully offline verification).
- **W3C Bitstring Status List** for cacheable, offline-checkable revocation.
- **OpenID Connect / OAuth 2.0** for cross-sector single sign-on.
- **EdDSA / Ed25519** for compact signatures suitable for QR and paper carriage.

Building on these open standards is deliberate: it keeps OpenResidency interoperable with any conformant wallet, verifier, or relying party, and avoids a proprietary lock-in that would disqualify it as a DPG.

## The nine DPG Standard indicators

1. **Relevance to SDGs.** Supports SDG 16.9 (legal identity for all) and, through inclusive service access, SDGs 1, 3, and 10. Residency credentials unlock health, tax, permits, and subsidy access for subnational populations.
2. **Open licensing.** Apache-2.0 (`LICENSE`), an OSI-approved license.
3. **Clear ownership.** Owned and stewarded by HarmonizedX Limited (RC 2011004, Abuja, Nigeria). Copyright is recorded in `NOTICE`, ownership and maintainership in `GOVERNANCE.md`.
4. **Platform independence.** No mandatory closed-source dependency. Runtime is Node.js; the datastore is PostgreSQL (swappable behind the `ResidencyStore` port); the foundational core has no framework dependency.
5. **Documentation.** `README.md` (architecture, quickstart, onboarding), inline module docs, a runnable smoke test, and this file. Adopters should add an operator runbook and API reference.
6. **Non-PII data export / open data.** The system minimizes PII by design (no raw national ID stored, tokenized subject references). Any published artifact (DID document, status list) contains no personal data.
7. **Privacy and applicable laws.** The design supports data minimization and consent (per-client OIDC consent, national ID never shared with relying parties). Adopters must complete a DPIA and confirm alignment with the relevant data protection law (for example the Nigeria Data Protection Act) and the identity authority's usage terms.
8. **Standards and best practices.** Uses the open standards listed above and common security practice (secrets via environment/KMS, HMAC tokenization, short-lived tokens).
9. **Do no harm by design.** Threat considerations documented: exclusion risk mitigated by offline and feature-phone paths; over-collection mitigated by minimization; issuer key compromise mitigated by KMS custody and revocation. See the caveats in `README.md`.

## What an adopter completes before production

- Issuer key custody in an HSM/KMS.
- A real SSO authentication factor (OTP or Verifiable Presentation).
- The national ID API contract and legal basis with the identity authority.
- A data protection impact assessment and records of processing.
- Gateway integrations for USSD/SMS.

## Reuse beyond one country

Nothing in the core is Nigeria-specific. The same binary serves multiple jurisdictions at once (one config file each), which makes OpenResidency suitable as shared regional infrastructure rather than a single-country fork.
