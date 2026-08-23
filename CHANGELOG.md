# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) under the pre-1.0 rules
stated in [`RELEASING.md`](RELEASING.md): while the version is `0.x`, a **minor** bump may
change behaviour an adopter depends on, and a **patch** never does.

Conformance state belongs to the suite, not to this file. `npm run conformance:orcs` prints the
current ORCS §15 position; where the two disagree, the suite is right.

## [Unreleased]

Nothing yet. The entries below become `0.1.0` when the first tag is cut.

## 0.1.0 — unreleased

The first release. Everything is new, so this section describes what the release *contains*
rather than what changed in it.

### Added

**Foundational identity.** Verification against any national ID source, selected by
configuration rather than code: REST/JSON (`GENERIC_REST`), XML/SOAP (`GENERIC_XML`), an
imported CSV/JSON/YAML register (`DATASET_FILE`), Nigeria's NIN, India's Aadhaar, MOSIP ID
Authentication with eKYC retrieval, and an external OpenID Provider acting as the register.
Eight adapters behind one registry, sharing a single declarative mapping layer.

**Residency issuance.** Four policy gates read from the jurisdiction's YAML — declared
subnational unit, foundational assurance floor, applicant-to-identity binding, and proof of
residence — each failing closed. Configurable Resident ID formats with entropy and checksum
validation. Refused applications are recorded with a reason and an appeal path.

**Residency lifecycle.** A relationship states the ORCS §4.3 attributes about itself and can be
suspended, reinstated or ended, so a residency that has stopped holding is recorded as such
rather than only having its credential revoked ([ADR-0007](docs/adr/0007-residency-status-is-lifecycle.md)).

**Credentials.** W3C Verifiable Credentials 2.0 in both `jwt_vc_json` and `ldp_vc`, signed
Ed25519. Bitstring Status List revocation carrying reason, authority and appeal path. Issuance
over OpenID4VCI and presentation over OpenID4VP. Offline verification against a cached issuer
key, single-QR carriage, and verification of `Ed25519Signature2020/2018` and `RsaSignature2018`
from other issuers, per federated peer and verify-only.

**Issuer key custody.** A `Signer` port with PKCS#11 (HSM), Google Cloud KMS, AWS KMS and
environment-JWK backends. The private key never enters the process under the first three. The
server refuses to boot in production with no key configured.

**SSO.** An OpenID Connect provider with Authorization Code + PKCE, pairwise subject
identifiers, per-relying-party scopes, and `acr`/`amr` derived from the factors actually
presented. Sign-in binds a real factor — a Verifiable Presentation, a WebAuthn passkey, or a
one-time code to the registered number. The national ID is never released.

**Consent and legal basis.** Revocable consent records with signed, portable receipts, stating
the ORCS §9 attributes. `legalBasisReference` resolves through the Legal Basis Registry; an
unregistered reference is refused rather than stored. Withdrawal destroys the OIDC grant and
revokes every token issued under it.

**Assurance.** A governed registry of canonical profiles, each versioned and attributed to the
authority that governs it, with per-provider ORCS §8.1 mappings. Identity assurance is kept
separate from authentication assurance by design.

**Privacy.** National IDs are never stored — only an HMAC-tokenised `subjectRef` peppered with a
deployment secret. Phone numbers are encrypted at rest. Erasure destroys identifying fields and
redacts the subject from the audit log while the hash chain still verifies. Per-jurisdiction
retention with dry-run sweeps and legal hold.

**Inclusion.** USSD and SMS reach feature phones for status checks and login codes, delivered to
the number bound to the record rather than back down the USSD session.

**Operations.** Role-scoped operator identity with per-operator API keys and rotation, a
tamper-evident hash-chained audit log with anchoring, non-PII statistics export with small-cell
suppression, Kubernetes manifests and a Helm chart, OpenAPI 3.1, and a typed SDK.

### Security

- The server refuses to start in production without `SUBJECT_PEPPER`. The fallback pepper is
  published in this source, so a deployment using it would have enumerable subject references
  and linkable pairwise OIDC subjects (#124).
- Operator authorisation required on the `/identity` endpoints (#139).
- One-time code attempts bounded per resident, closing an unbounded-guess path (#94).
- A federated peer's status list is authenticated before it is believed (#90).
- The audit chain is anchored, so truncation is detectable rather than merely unlikely (#119).

### Notes

- `npm run conformance:orcs` does not yet report all nine ORCS §15 criteria as PASS. The
  remaining failures are capabilities not yet built — conflict detection, identity-link
  lifecycle, and the event layer — and are tracked, not hidden.
- No MOSIP certification, compliance or partnership is claimed. The MOSIP suites verify against
  reference implementations and published behaviour, never a live deployment.
