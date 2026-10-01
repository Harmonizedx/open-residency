# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) under the pre-1.0 rules
stated in [`RELEASING.md`](RELEASING.md): while the version is `0.x`, a **minor** bump may
change behaviour an adopter depends on, and a **patch** never does.

Conformance state belongs to the suite, not to this file. `npm run conformance:orcs` prints the
current ORCS §15 position; where the two disagree, the suite is right.

## [Unreleased]

### Added

**A first residency from a spreadsheet.** `docs/FIRST-RESIDENCY.md` takes a jurisdiction with
no HSM, no KMS and no national ID API from a register extract to a signed, verifiable
credential, every command run as written against a real database with `NODE_ENV=production`.
`npm run keys:issuer` generates the issuer signing key for the `env` backend, which nothing
documented how to produce. The npm package page now says what has to be running before the
client is useful.

**Identity links (ORCS §11).** Which external identifiers belong to which person is now a
record with a history rather than a column. Every identifier is linked with evidence, can be
disputed (which blocks issuing or delivering a credential until somebody has reviewed it),
unlinked with a reason, and relinked to the right person after adjudication; a duplicate
record can be merged into the survivor and a merge reversed. Nothing is deleted: a closed
link keeps its dates and reasons and points at the link that continues it, and every
operation appends an event naming who did it and why. Enrolment resolves through the links,
so a corrected mapping is what the register acts on. Unlinking the foundational identifier
suspends the relationship first, as ORCS §7 asks. Ten operator routes under `/residency`,
the same operations in the SDK, and ORCS §15 criterion 6 now passes. (ADR-0014)

### Fixed

- With `ISSUER_KEY_BACKEND=env` and no separate `OIDC_SIGNING_JWK`, the application refused
  to start: the SSO layer publishes its signing key as a JWK and the imported issuer key was
  not exportable. The key arrives as a JWK in the environment, so it is now imported
  extractable, which reveals nothing that was not already there. Every no-KMS deployment hit
  this.

### Changed

- `npm start` and `npm run start:dev` load `.env`. The quick start has said to copy
  `.env.example` to `.env` since the first release, and nothing read it.

### Security

- axios 1.19.0 to 1.20.0 for ten advisories (GHSA-vh66-26gq-q6x8, GHSA-9fr6-4gfg-3,
  GHSA-c29m-xwm3-cm6r, GHSA-mghh-pgcx-3jjj, GHSA-x97p-jq2g-jp4f, GHSA-3pq3-5fj3-cg6v,
  GHSA-542g-h47m-68v8, GHSA-j8rh-479h-cp32, GHSA-4hqw-qxg8-jxx2, GHSA-m8m8-qj5v-23w3). Not
  transitive: axios is how the foundational REST, XML and MOSIP adapters and the messaging
  providers reach outside systems. What was possible before the fix: a hostile or compromised
  identity source could stall the event loop with a crafted redirect, or steer a request past
  the configured proxy. (#179)

## 0.2.1 — 2026-09-30

A security patch, cut as soon as the fix was available, as RELEASING.md asks. It also
carries the rewritten `@openresidency/sdk` package page, which reaches npm with this publish.

### Security

**Rate limiting counted the proxy, not the caller.** The in-app limit (120 requests a minute
by default) keyed on the socket address, and nothing told Express to trust a proxy, so behind
the ingress the shipped Kubernetes and Helm manifests put in front, every request presented
the ingress's address and the whole deployment shared one bucket. One client could exhaust
it and hold every registrar at 429. The key now comes from a declared number of trusted proxy
hops (`TRUSTED_PROXY_HOPS`, default `0`), and nothing the caller controls reaches it. When a
request carries `X-Forwarded-For` while no hop is declared, the application logs once that it
is behind a proxy it was not told about. The manifests set one hop to match their ingress.
Per-operator budgets, which would stop a busy office behind one address sharing a bucket,
are a separate change and are recorded as deferred in ADR-0013. (#147)

### Changed

- The npm page for `@openresidency/sdk` now opens with what OpenResidency is and which
  reader you are (a service checking a credential, a registrar, a wallet), says that
  refusals and invalid credentials are results rather than exceptions, and tables which
  role each call needs. The client itself is unchanged. (#175)

## 0.2.0 — 2026-09-30

The SDK now reaches the whole API, and the API description it is generated from is held to
the server by CI. Under the pre-1.0 rules a minor bump may change behaviour; the one
behavioural change is listed under **Changed**.

### Added

**The SDK covers every operation.** `@openresidency/sdk` 0.1.0 had 14 methods against 80
routes; the relationship and credential lifecycle, assurance, OpenID4VP, VC-API and the
offline surface were unreachable through it. It now has named methods for the
integrator-facing surface (lifecycle transitions, refusals, reconcile, assurance, legal bases,
operator identity, statistics, offline, OpenID4VCI, OpenID4VP, VC-API, trust material) and a
`request(method, path, opts)` that reaches every operation, typed from the OpenAPI contract.
The 0.1.0 methods and their return types are unchanged. Per-call credentials cover the
wallet access token and the USSD secret. (#169)

**`docs/openapi.yaml` documents every route** (80, from 43), and two CI checks keep it that
way: a controller route missing from the spec fails the build, and so does a stale generated
SDK contract. (#169)

**The SDK is published by the release workflow** through npm trusted publishing, with
provenance naming the commit and run that built it. 0.1.0 was published by hand and has
none. (#165)

### Changed

**`POST /operator/operators/{id}/disable` acts on the operator in its path.** It previously
read `operatorId` from the body and ignored the path, so a request could name one operator
in the URL and disable another. A body `operatorId` is still accepted but must equal the
path id; a different value is now a 400. (#171)

**The OpenAPI description was corrected against the controllers in 59 places.** Every POST
without an explicit status answers 201, not the 200 the spec claimed; each guarded operation
states its required role; the 400/401/403/404/503 responses the code returns are listed;
request constraints and `required` lists match the DTOs; response schemas carry the fields
the code returns (the resident record on issue, `offline` on verification, `subjectRef` on
consents, the audit chain's anchoring fields); `POST /offline/qr` is documented as the JSON
it returns rather than SVG. Server behaviour is unchanged; a client generated from the old
spec would have mis-parsed some of it. (#169)

### Deprecated

- `operatorId` in the body of `POST /operator/operators/{id}/disable`; the path names the
  operator. (#171)
- `authority` in the body of `POST /consent/legal-bases/{id}/deactivate`. It was required
  and ignored; it is now optional and ignored. The authenticated operator is recorded. (#172)

### Fixed

- The SDK did not build under TypeScript 6 and `npm pack` shipped a stale `dist/` from July
  alongside the sources. The root package is marked private so the server cannot be
  published by accident. (#164)

### Security

- undici 6.28.0 to 6.29.0 for GHSA-3wwx-pv8p-q78v, GHSA-r53p-7pc4-xj5r and
  GHSA-rfgv-xxqx-mfg5, and js-yaml 5.3.0 to 5.4.2 for GHSA-r3ph-w7gj-g6xm. Both are
  transitive: undici reaches this tree only through jsonld's HTTP client, which uses neither
  WebSockets nor the retry interceptor the advisories concern, and js-yaml is read on
  configuration files the deployer controls. No exposure is known; the bump keeps the
  dependency audit clean. (#170)

## 0.1.0 — 2026-09-24

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
- **Health endpoints.** `GET /health/live` and `GET /health/ready`; readiness asks the
  database and answers 503 when it does not. Unauthenticated, exempt from rate limiting.
  The Helm chart and raw manifests probe these instead of `/residency/countries`, which
  read from memory and reported a pod healthy with its database gone.
- **Operations log.** JSON lines to stdout through one logger (`LOG_LEVEL`), Nest's own
  messages included. Every response carries an `x-request-id`; each request is logged as
  method, route pattern, status, duration and that id — never the URL, body or a header.
  Sensitive keys (`identifiers`, `nin`, `sample`, `authorization`, …) are redacted wherever
  they appear in a logged object. `npm run smoke:observability` asserts that a submitted
  identifier reaches neither the log nor a metric label. Startup is one JSON line in the same
  stream; a boot refusal is a `fatal` line there too.
- **Prometheus metrics** on a separate `METRICS_PORT` (unset = off), so the ingress never
  routes to it: HTTP duration by route pattern and status; issuance outcomes by status,
  refusal-reason class and declared unit; foundational verification outcome and duration
  by provider; last-success timestamps for the three background jobs. Every label value is
  drawn from a bounded set.
- `SIGTERM` now runs the module shutdown hooks (timers stop, the HSM session is released)
  rather than ending the process mid-request.
- **The container image is published.** A tag push builds
  `ghcr.io/harmonizedx/open-residency:vX.Y.Z` from the tag, scans it, pushes it, signs it by
  digest (keyless) and attests provenance and an SBOM in the registry; the release notes name
  the digest. Version tags only — no `latest`. The Helm chart defaults to the chart's
  `appVersion` and accepts `image.digest` to pin the bytes; the raw manifests pin `v0.1.0`.
  Previously every manifest pointed at `ghcr.io/your-org/openresidency:latest`, which did not
  exist.

### Security

- The server refuses to start in production without `SUBJECT_PEPPER`. The fallback pepper is
  published in this source, so a deployment using it would have enumerable subject references
  and linkable pairwise OIDC subjects (#124).
- Operator authorisation required on the `/identity` endpoints (#139).
- One-time code attempts bounded per resident, closing an unbounded-guess path (#94).
- A federated peer's status list is authenticated before it is believed (#90).
- The audit chain is anchored, so truncation is detectable rather than merely unlikely (#119).
- The runtime dependency audit is clean again at the CI gate (`npm audit --omit=dev
  --audit-level=moderate`). `@nestjs/common`, `@nestjs/core` and `@nestjs/platform-express`
  move to 11.2.6, taking `multer` to 2.4.0 past three denial-of-service advisories
  (GHSA-wc9g-mqfw-jrwm, GHSA-qfvm-cv95-jqjf, GHSA-535w-7cp7-47q4); `qs` (GHSA-x5fp-wj9c-mxmx,
  GHSA-4mjr-xmp4-gh2g) and `fast-uri` (four SSRF/host-confusion advisories, fixed in 3.1.6) are
  updated in place. `mysql2`,
  which the Prisma CLI pins at a version with a credential-leaking auth-plugin downgrade, is
  overridden to `^3.24.4` — the reasoning and the removal condition are in `SECURITY.md`'s
  override table. Nothing in this deployment opens a MySQL connection.

### Notes

- `npm run conformance:orcs` does not yet report all nine ORCS §15 criteria as PASS. The
  remaining failures are capabilities not yet built — conflict detection, identity-link
  lifecycle, and the event layer — and are tracked, not hidden.
- No MOSIP certification, compliance or partnership is claimed. The MOSIP suites verify against
  reference implementations and published behaviour, never a live deployment.
