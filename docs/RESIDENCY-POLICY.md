# OpenResidency — Residency Policy Platform

Status: **Proposed** · **Single source of truth** — this document consolidates the
architecture decision (Part I), the target design (Part II), and the repo-grounded
implementation blueprint (Part III). It supersedes the earlier separate `ADR 0001` and
`POLICY-ENGINE-BLUEPRINT.md` files.

It defines the one remaining differentiating capability for OpenResidency: a configurable,
explainable, **rights-preserving** Residency Policy Engine. All identity, credential,
federation, SSO, and trust infrastructure are treated as **foundational services already
shipped**; the policy engine is the product's differentiating layer, built on top of them.

---

# Part I — Decision (ADR 0001)

- Status: **Proposed** · Date: 2026-07-17 · Deciders: HarmonizedX (maintainers)

## Context

The repository currently expresses residency policy as three fields (`minAssurance`,
`proofOfResidence` enum, `allowProvisional`) in `src/core/config/country-config.ts`, and
the issuance decision is a single hardcoded assurance-rank comparison in
`src/core/residency/residency-service.ts`.

Residency policy is where real-world variation lives. It differs across every subnational
unit within a country, across countries, across categories of person (ordinary, temporary,
student, worker, displaced, institutional, dependent), and across the purpose it is used
for (healthcare, tax, education, housing, electoral, immigration). A boolean or a
three-value enum cannot express this, and a system that encoded any one jurisdiction's
rules in code could not be reused as a Digital Public Good.

## Decision

Build OpenResidency as a **jurisdiction-neutral residency policy platform**. Specifically:

1. **No jurisdiction-specific rule lives in `src/core/`.** The core reasons over abstract
   primitives; every country/region/programme fact lives in a signed, versioned **policy
   pack** loaded at runtime. Nigeria is reference pack #1 of N, never a premise.
2. **Five separated layers:** identity assurance → residency determination → credential
   assurance → service eligibility → authentication/SSO. A residency credential is an
   input to eligibility, never a substitute for it.
3. **Residency is a time-bound, evidence-backed, jurisdiction-scoped, policy-versioned
   status**, not a boolean. Every determination is explainable (which rules fired) and
   reproducible (policy version pinned to the credential).
4. **Residency is separated from origin/ancestral status.** Origin registers (indigene,
   hukou, domicile, Heimatort, tribal registers) are a separate credential type + issuing
   authority + pack. A sealed baseline rule forbids origin from affecting ordinary-residency
   eligibility.
5. **Decisions are declarative data, evaluated by a small deterministic evaluator that
   emits `satisfiedRules[]`/`failedRules[]`.** An authoring DSL or delegation to
   OPA/Cedar/JSON Logic/CEL is a later layer, not the foundation. A risk score may trigger
   review but never invents legal eligibility.
6. **Layered packs with enforced sealed fields.** The global baseline encodes a
   human-rights floor (UDHR, ICCPR, UN SDG 16.9, World Bank ID Principles); lower layers
   cannot override sealed fields — the resolver rejects such overrides at merge time.
7. **Privacy and governance are configured and enforced.** Packs declare lawful basis,
   retention, and disclosure; the runtime enforces tokenization, retention jobs, and
   per-service gating, and rejects unsigned or expired packs in production.

## Scope boundary (core-OSS vs deployment)

Core ships **engines, schemas, interfaces, and reference packs**. Manual-review/appeals
UI, the equity-simulator dashboard, exotic evidence adapters, and field-verification apps
are deployment concerns — the core provides the state machine, the headless conformance
runner, and the adapter ports, not the applications.

## Consequences

- **Positive:** genuine reuse across jurisdictions; explainable, appealable, reproducible
  decisions; strong DPG alignment (non-discrimination, privacy-by-design, open standards);
  backward-compatible migration (today's flat config = a pack with no overrides).
- **Cost:** a new policy-engine subsystem, an evidence model, a generic jurisdiction model,
  and pack signing/governance — delivered in phases (Part III), evolving the existing tree
  in place rather than restructuring it.
- **Rejected alternatives:** (a) extend the enum per country — does not scale and leaks
  jurisdiction logic into core; (b) adopt Rego/Cedar as the foundation — opaque outputs
  fight the explainability requirement; (c) wholesale repo restructure into a new tree —
  discards working, conformance-tested code for no functional gain.

---

# Part II — Design (north-star architecture)

The [roadmap in Part III](#part-iii--implementation-blueprint-repo-grounded) says what
actually gets built, in what order, so the repository never stops working while we get
there.

## 1. The first constraint: jurisdiction neutrality

There is no single residency rule that fits every country, every subnational unit, every
category of person, or every government service. The core software must therefore contain
**no** country-, region-, or programme-specific rule. It reasons only over abstract
primitives. Every jurisdiction-specific fact — including every one of Nigeria's — lives in
a signed, versioned **policy pack** loaded at runtime.

> **The bug test.** If a rule names a country, a subnational unit, a document type, a
> legal instrument, or a residency threshold, and it lives in `src/core/`, that is a bug.
> It belongs in a policy pack.

Nigeria is **reference pack #1 of N** — a worked example proving the model generalizes, a
peer of a unitary-municipality pack, a displaced-person/host-community pack, and a
student-residency pack. It is never the premise.

The human-rights floor that packs may **not** override is itself expressed as a pack — the
**global baseline** — and is grounded in jurisdiction-neutral instruments so it is
defensible anywhere:

- Freedom of movement and residence — UDHR Art. 13, ICCPR Art. 12
- Legal identity for all — UN SDG 16.9
- Universal coverage, non-discrimination, barrier removal — World Bank *Principles on
  Identification for Sustainable Development*
- Assurance frameworks — eIDAS, NIST SP 800-63, ISO/IEC 29115 (a deployment picks its
  mapping; the core commits to none)

A country's own constitution or data-protection statute then appears as *that country
pack's citation for the same floor* — never as the source of the floor in core code.

## 2. Five independently configurable layers

The platform separates concerns that bespoke state systems routinely conflate. Each layer
is configured on its own and can be reasoned about, tested, and audited in isolation.

| # | Layer | Question it answers | Where in the code |
|---|-------|---------------------|-------------------|
| 1 | **Identity assurance** | Who is the applicant? | `src/core/foundational/*`, `src/core/proofing/*` |
| 2 | **Residency determination** | What recognised relationship does this person have with this jurisdiction, right now? | `src/core/residency/*` + new `policy-engine` |
| 3 | **Credential assurance** | What claim can the authority safely issue, and in what form? | `src/core/credentials/*`, `oid4vci`, `oid4vp` |
| 4 | **Service eligibility** | Which specific service or programme can this resident access? | new `eligibility` engine (evolves the OIDC scope model in `src/sso/*`) |
| 5 | **Authentication & SSO** | How does the person securely use those services? | `src/sso/*` |

A resident credential from Layer 3 is an **input** to Layer 4, never a substitute for it.

## 3. Residency is a status, not a boolean

Do **not** model residency as `{ "isResident": true }`. Model it as a time-bound,
evidence-backed, jurisdiction-scoped, policy-versioned **status**:

```json
{
  "jurisdiction": "REGION-001",
  "residencyClass": "ordinary_resident",
  "status": "active",
  "effectiveFrom": "2026-04-01",
  "verifiedAt": "2026-07-16",
  "assuranceLevel": "substantial",
  "policyVersion": "region-001-residency-2.1",
  "evidenceProfile": "address-plus-authoritative-record",
  "expiresAt": "2027-07-16"
}
```

Two properties are non-negotiable for public infrastructure:

- **Explainable.** Every determination records which rules fired and on what evidence, so
  it can be reviewed, appealed, and audited. This feeds the tamper-evident hash-chained
  audit log the platform already ships (`src/core/audit/*`).
- **Reproducible.** `policyVersion` is pinned to the credential at issuance. A rule change
  tomorrow never retroactively invalidates a status issued today, and any past decision
  can be recomputed against the exact policy that produced it.

## 4. Separate residency from origin/ancestral status

Residence and ancestral origin are **different concepts** and must never be conflated. The
core models an abstract origin/ancestral connection as an **optional, separate credential
type with its own issuing authority and its own policy pack** — it is never asserted as a
side effect of a residency determination.

```
national citizenship  ≠  jurisdiction residency  ≠  origin/ancestral status  ≠  programme eligibility
```

A `ResidentCredential` proves "this person currently resides in, or has a recognised
connection to, this jurisdiction." It must **not** also assert "this person originates from
here." Origin/ancestral registers exist under many names worldwide — and each is a pack's
concern, not the core's:

| Local instrument | Jurisdiction (example) |
|---|---|
| *indigene* certificate | Nigeria |
| *hukou* (户口) | China |
| domicile certificate | India |
| *Heimatort* | Switzerland |
| tribal / ethnic registers | various |

The **global baseline pack** carries a *sealed* rule (see §10): origin or ancestry must not
affect ordinary-residency eligibility. No country pack can re-enable such discrimination
through configuration.

### Credential-type taxonomy

All are optional and enabled per pack:

`ResidentCredential` · `TemporaryResidentCredential` · `StudentResidentCredential` ·
`WorkerResidentCredential` · `HouseholdMemberCredential` ·
`DisplacedPersonResidentCredential` · `IndigeneOrOriginCredential` (separate authority) ·
`ServiceEligibilityCredential`

## 5. Generic jurisdiction model

No administrative tier — state, province, LGA, ward, county, municipality, district,
prefecture — is hard-coded. Jurisdictions are a generic recursive object:

```yaml
jurisdiction:
  id: "REGION-001-DIST-07"
  name: "District 7"
  type: "district"              # free label; the tier's local name
  parent: "REGION-001"
  country: "XX"
  administrative_level: 2        # depth, not a fixed enum
  timezone: "UTC"
  boundary_reference: "geo-boundary-v3"
  policy_pack: "district-07-residency-1.0"
```

This expresses a federal `country → state → LGA → ward → community` hierarchy and a unitary
`country → municipality → district` hierarchy with the same primitive. The current
`subnationalUnit` enum (`state | province | region | lga | ward | county`) becomes an open
label plus a numeric level.

## 6. Evidence catalogue, classified by source quality

Residency evidence varies enormously across jurisdictions, so the core does not enumerate
documents. It defines **source classes** by evidential quality, and packs map local
document types onto them:

| Source class | Meaning | Examples |
|---|---|---|
| **Authoritative** | Read directly from a recognised source | population/tax/property/immigration/social-protection register, utility provider API, school registry, payroll, health-insurance DB |
| **Corroborative** | Applicant-submitted, independently checked | utility bill, tenancy agreement, bank correspondence, employer letter, admission record |
| **Attested** | Confirmed by an authorised person | community leader, ward officer, landlord, employer, humanitarian org, local-government officer |
| **Observed** | Established by inspection | physical address visit, remote video, geolocation, enrolment-centre confirmation |
| **Self-declared** | Applicant-provided, not yet independently confirmed | |

Evidence is represented uniformly, so rules reason over structure, not document names:

```json
{
  "evidenceType": "utility_account",
  "sourceClass": "authoritative",
  "issuer": "Example Utility Co.",
  "subjectMatch": true,
  "addressMatch": true,
  "jurisdictionMatch": true,
  "issuedAt": "2026-06-01",
  "validUntil": "2026-09-01",
  "verificationMethod": "issuer_api",
  "confidence": 0.94
}
```

Proof-of-address regimes internationally combine recency, named-account, and
multiple-independent-document requirements — all expressible over these fields.

## 7. Declarative, explainable decisions — not application code, not a raw score

**Decision logic never lives in application code.** No `if (region === "X" && hasBill)`.
Rules are declarative data:

```yaml
rules:
  ordinary_resident:
    all:
      - identity.assurance >= "substantial"
      - applicant.age >= 18
      - jurisdiction.address_match == true
    any:
      - evidence.authoritative_residency.count >= 1
      - all: [ evidence.corroborative.count >= 2, evidence.independent_issuers >= 2 ]
      - all: [ evidence.attestation.count >= 1, evidence.physical_verification.passed == true ]
    exclusions:
      - identity.status == "deceased"
      - fraud.risk == "critical"
```

The output is **explainable by construction** — which rules were satisfied, which failed,
under which policy version:

```json
{
  "decision": "approved",
  "residencyClass": "ordinary_resident",
  "satisfiedRules": ["R-ORD-02"],
  "failedRules": [],
  "policyVersion": "2.1.0",
  "assuranceLevel": "substantial",
  "explanationCode": "AUTHORITATIVE_ADDRESS_MATCH"
}
```

Two deliberate engineering commitments:

- **A rule set, not a bare score.** A risk score may route a case to additional review; it
  must never *silently invent legal eligibility*. Legal eligibility is a satisfied rule
  with a stated basis.
- **A small deterministic evaluator before any authoring language.** The explainability
  requirement is trivial when rules are plain data evaluated step-by-step, and hard when a
  request goes into an opaque engine and a boolean comes back. So v1 is a purpose-built
  evaluator over the structure above. A human-readable authoring DSL, or delegation to
  OPA/Rego, Cedar, JSON Logic, or CEL, is a *later* surface layered on top — **not** the
  foundation. Building the language first is the trap; we do not.

## 8. Service eligibility is a separate engine

A valid resident credential does **not** auto-qualify anyone for every service. Residency
status and service eligibility are computed by different engines over different policies:

```
Residency Policy Engine  →  resident status
Service Eligibility Engine  →  access to a specific benefit/service
```

```yaml
service_policy:
  service: "scholarship-2027"
  requirements:
    - credential.type == "ResidentCredential"
    - credential.status == "active"
    - residency.continuous_duration_days >= 365
    - applicant.student_status == "verified"
    - applicant.age <= 30
```

The same person can be eligible for emergency healthcare immediately, a scholarship after
12 months, and a housing programme after 24 months + an income test — all from one
residency status, three service policies.

**Context-scoped residency.** Purposes define residency differently (physical, ordinary,
habitual, legal, tax, electoral, education, healthcare, immigration, programme). These are
policy **contexts**, and a determination in one context is **not** reusable in another
unless the receiving policy explicitly accepts it.

## 9. Assurance configured separately, mapped per deployment

The core uses neutral internal levels — `basic`, `substantial`, `high` — decoupled from
eligibility. A deployment maps them onto its own framework (NIST IAL/AAL, eIDAS
low/substantial/high, ISO/IEC 29115, or a national scheme). Assurance answers "how sure are
we of identity + binding," which is orthogonal to "does this person qualify."

## 10. Layered configuration with sealed controls

Packs compose by precedence, each layer overriding only fields the layer above marks
overridable:

```
global baseline → country baseline → state/province → municipality/LGA → programme → case exception
```

```yaml
extends:
  - "global/residency-core@2.0"
  - "countries/xx/privacy-and-rights@1.1"
  - "regions/001/residency@2.1"
overrides:
  credential.validity_days: 730
  ordinary_resident.minimum_duration_days: 90
```

**Sealed fields are enforced, not conventional.** The global baseline marks the
human-rights floor `sealed`; the resolver **rejects** an override attempt at merge time
rather than silently dropping it. This is what makes "a jurisdiction cannot disable
mandatory rights, privacy, or security controls" a guarantee instead of a hope:

```yaml
# global/residency-core@2.0
sealed:
  - residency.origin_must_not_affect_ordinary_eligibility
  - privacy.national_identifier.expose_in_credential   # forced false
```

## 11. Cross-cutting requirements

These apply across all five layers and all packs.

### 11.1 Inclusive & exceptional evidence pathways
A system built only around utility bills excludes people in informal settlements, tenants
whose bills are in a landlord's name, children, displaced persons, people living with
relatives, nomadic communities, homeless and institutional residents, rural communities
without formal addresses, persons with disabilities, and people without smartphones. Every
pack **must** supply alternative pathways (host attestation, community attestation, field
verification, social-registry match, humanitarian records, guardian + relationship proof).
**No automated rejection may occur solely because a conventional address document is
absent** — this is enforced as a sealed baseline rule.

### 11.2 Households & relationships
First-class `Person`, `Household`, `Address`, `Relationship`, `Jurisdiction`, `Evidence`,
`ResidencyDetermination`, `Credential`. Household structure is not assumed nuclear:
guardians, shared accommodation, institutions, and non-family households are supported.

### 11.3 Time, continuity, interruption
The engine computes current / continuous / cumulative residency, temporary absence,
address change, inter-jurisdiction movement, multiple/principal/seasonal residence,
departure, and return. History is **append-only**: on a move, close the prior period and
open a new one — never delete.

### 11.4 Determination lifecycle
`draft → evidence submitted → identity verified → evidence validated → automated assessment
→ {approved | more-evidence | manual review | rejected} → credential issued → active →
{renewed | suspended | revoked | expired | transferred}`. Supports rejection reasons,
evidence requests, manual overrides (officer + reason code + legal basis + supervisor
approval), appeals, corrections, and full audit history.

### 11.5 Privacy — declared *and enforced*
Packs declare data collected, purpose, lawful basis, retention, access roles, credential
disclosure, and per-service sharing. **Declaration is documentation until the runtime
enforces it** — the value is in tokenizing national identifiers (already done via the HMAC
`subjectRef`), running real retention/expiry jobs, and gating disclosure per service. We
ship enforcement for every field a pack is allowed to declare.

### 11.6 Governance & signing
Every published pack carries owner, legal/privacy/technical approvers, version, effective
and review/expiry dates, changelog, digital signature, and rollback instructions. **The
runtime rejects unsigned or expired packs in production.**

### 11.7 Conformance & simulation
Every pack ships test cases (including a mandatory "origin must not affect ordinary
residency" case) run headlessly in CI — consistent with how VC/OpenID4VCI/OpenID4VP
conformance is already gated. A later **equity simulator** surfaces likely qualification
rates, disproportionately rejected groups, top rejection-driving rules, and evidence
reliance, so authorities catch discriminatory or impractical rules *before* deployment.

---

# Part III — Implementation blueprint (repo-grounded)

The actionable build plan, written against what the repository **already ships**, so it
extends the working platform in place rather than restarting it.

## 0. What already exists — build ON this, do not rebuild it

Everything below is implemented and tested (~449 checks across the smoke + conformance
suites), and is treated here as **foundational service**, not part of the policy-engine
work:

| Capability | Where | Reused by the engine as |
|---|---|---|
| Multi-source identity verification (REST/XML/dataset) + tokenized `subjectRef` | `src/core/foundational/*`, `mapping.ts` | Layer 1 identity assurance input |
| Owner-binding + proof-of-residence (RAL) + biometric attestation | `src/core/proofing/{binding,residence,biometric}.ts` | Evidence + assurance inputs |
| Credential issuance (VC-JWT + Data Integrity), **pluggable Signer with HSM/KMS backends** | `src/core/credentials/{vc-issuer,ldp-issuer,signer,signers,status-list,did}.ts` | Decision **and pack** signing; credential output |
| Wallet issue/present | `src/core/oid4vci/*`, `src/core/oid4vp/*` | Credential delivery + presentation |
| SSO IdP: pairwise subjects, WebAuthn/OTP/VP, `acr/amr` assurance, **multi-issuer federation** | `src/core/sso/*`, `src/sso/*` | Layer 5 auth; eligibility scope surface |
| Operator identity + RBAC + MFA | `src/core/operator/*` | Manual-review / appeals authorization |
| **Tamper-evident hash-chained audit log** | `src/core/audit/audit-log.ts` | Where every decision + override is written |
| Revocable consent + signed receipts | `src/core/consent/consent.ts` | Per-service disclosure + lawful-basis record |
| Zod-validated per-jurisdiction config, loaded from YAML | `src/core/config/country-config.ts` | Becomes the **policy pack loader** |

**The policy the platform enforces today** is the thin `residencySchema` block
(`minAssurance`, `proofOfResidence`, `allowProvisional`, `applicantBinding`, `residence`)
evaluated by the `ASSURANCE_RANK` comparison + gates in
`src/core/residency/residency-service.ts#issue()`. **That is exactly what the engine
replaces — incrementally, and backward-compatibly** (§4 below).

## 1. Core components → concrete repo mapping

| # | Component | New module / extend | Reuses |
|---|---|---|---|
| 1 | Jurisdiction Registry (generic recursive model; no hard-coded tier) | **new** `src/core/jurisdiction/` | generalizes `subnationalUnit` in `country-config.ts` |
| 2 | Residency Policy Engine (evaluator) | **new** `src/core/policy-engine/` | replaces `ASSURANCE_RANK` gate in `residency-service.ts` |
| 3 | Evidence Catalogue (source-class schema) | **new** `src/core/evidence/catalogue.ts` | proofing `residence.ts` evidence model as seed |
| 4 | Evidence Engine (normalization + scoring) | **new** `src/core/evidence/` + adapter **port** | foundational `mapping.ts` pattern; 2–3 reference adapters only |
| 5 | Decision Engine (`satisfiedRules`/`failedRules`, signed) | part of `policy-engine/` | `credentials/signer.ts` to sign decisions; `audit/` to record |
| 6 | Human-Rights Floor (sealed baseline pack + merge resolver) | **new** `src/core/policy-engine/floor.ts` + `config/packs/global/` | pack loader; conformance runner |
| 7 | Policy Signing & Registry | **new** `src/core/policy-engine/registry.ts` | `credentials/signer.ts` + KMS backends (already built) |
| 8 | Appeals Engine (determination lifecycle) | **new** `src/core/residency/lifecycle.ts` | `operator/*` for authz; `audit/` for history |
| 9 | Service Eligibility Engine (separate) | **new** `src/core/eligibility/` | evolves the OIDC scope model in `src/core/sso/*` |
| 10 | Residency Credential Issuer (typed + selective disclosure) | **extend** `src/core/credentials/*` | existing VC-JWT/LDP issuers + `Signer`; add SD-JWT |

## 2. Policy pack structure

A pack is a **signed, versioned** document loaded at runtime — the natural evolution of a
country YAML. It lives in `config/packs/`, is validated by a Zod schema exactly like
`country-config.ts`, and is signed/verified through the existing `Signer` (so KMS custody
is inherited, not reinvented):

```
config/packs/
  global/residency-core@2.0.yaml        # the SEALED human-rights floor
  countries/ng/privacy-and-rights@1.1.yaml
  jurisdictions/ng-katsina/residency@2.1.yaml
  programmes/subsidy-2027.yaml
  examples/                             # federal-state, unitary-municipality,
                                        # displaced-person, student-residency
```

Each pack carries: `metadata` (owner, approvers, version, effective/expiry dates,
changelog), `residencyClasses`, `evidenceRequirements`, `rules` (declarative
`all`/`any`/`exclusions`), `exceptions`, `lifecycle`, `legalAuthority`, `tests`, and
`signature`. **No application-code change is required to add a jurisdiction.**

## 3. The sealed human-rights floor — Phase 1, non-negotiable

The correction that matters most: the floor ships **with** the evaluator, not later, so the
*first* runnable engine is rights-preserving by construction.

`config/packs/global/residency-core@2.0.yaml` marks these `sealed`; the merge resolver in
`policy-engine/floor.ts` **rejects an override at load time** (it does not silently drop
it), and the platform **refuses to boot a pack that violates the floor**:

```yaml
sealed:
  - residency.origin_must_not_affect_ordinary_eligibility      # the indigene/settler guard
  - residency.no_auto_reject_on_missing_address_document        # the inclusion guarantee
  - privacy.national_identifier.expose_in_credential: false     # NIN never in a credential
```

Every pack must ship a **mandatory conformance test** — including an "origin must not
affect ordinary residency" case — run headlessly in the smoke/CI convention already used
for VC/OpenID4VCI/OpenID4VP conformance.

## 4. Roadmap (repo-grounded, corrected)

Each phase is additive, keeps `npm test` green, and adds its own `smoke:*` suite to the
chain. Today's flat `residency:` config keeps working throughout (§5).

**Phase 1 — evaluator + evidence schema + jurisdiction model + the sealed floor + CLI**
- Add `src/core/evidence/catalogue.ts` (source-class schema) and the `ResidencyDetermination`/status model.
- Add `src/core/policy-engine/` deterministic evaluator (`all`/`any`/`exclusions` → `satisfiedRules`/`failedRules`) and `floor.ts` (sealed-field merge resolver).
- Add `src/core/jurisdiction/` (recursive model; `subnationalUnit` becomes label + level).
- Ship the **sealed floor**, **origin-separation**, and **inclusion** rules from day one.
- Add a **CLI** (`scripts/policy.ts` → `dist-core`, per the existing smoke convention) to evaluate a pack against fixture evidence offline.
- **Backward-compat:** today's `residencySchema` is read as "a pack with no overrides"; `residency-service.ts#issue()` calls the evaluator but its default pack reproduces current behaviour.
- Tests: `smoke:policy` (evaluator + sealed-floor rejection + mandatory anti-discrimination case).

**Phase 2 — signing, registry, decision provenance**
- `policy-engine/registry.ts`: load, verify (via `credentials/signer.ts` + KMS), and **reject unsigned/expired packs in production**.
- Sign each **decision** and write it to `src/core/audit/*` (version + evidence + rules + explanation code) → **replayable years later**.
- Tests: `smoke:policy-registry`, `smoke:policy-decision`.

**Phase 3 — evidence engine + lifecycle/appeals**
- `src/core/evidence/`: normalization **port** (mirroring `foundational/mapping.ts`) + **2–3 reference adapters only**; assurance scoring mapped to `basic/substantial/high`.
- `src/core/residency/lifecycle.ts`: determination state machine + append-only history; manual overrides authorized via `operator/*`.
- Tests: `smoke:evidence`, `smoke:lifecycle`.

**Phase 4 — eligibility + typed credentials + selective disclosure**
- `src/core/eligibility/`: separate engine over service policies; evolves the OIDC scope model in `sso/*`.
- Extend `credentials/*` with residency **credential types** and **SD-JWT selective disclosure**.
- Tests: `smoke:eligibility`, extend `conformance`.

**Phase 5 — connector *port*, not seven connectors**
- Ship the **evidence/eligibility connector interface + 2–3 reference connectors** (e.g. identity, a utility/register, one sector). Additional connectors (tax, education, employment, community, immigration) are **deployment-pluggable**, not baked into core — per the scope line (Part I).

## 5. Backward-compatibility & "green at every step"

- The existing `residency:` config and every current country YAML **keep working** — they resolve to a pack with no overrides.
- `residency-service.ts#issue()` is migrated to call the evaluator, but its **default behaviour is byte-compatible** until a jurisdiction opts into a richer pack.
- **Nothing is removed until its replacement is in and tested.** Each phase adds a `smoke:*` suite to the `npm test` chain; the Postgres-backed boot job stays green.

## 6. Acceptance criteria

- The **same engine** serves multiple jurisdictions using **only different signed packs** — no code change.
- Every decision references the **exact policy version**, the **evidence evaluated**, the **rules passed/failed**, and is **reproducible years later** from the audit record.
- The **sealed human-rights floor cannot be overridden** by any pack (rejected at merge; proven by a mandatory conformance test in every pack).
- **No automated rejection** occurs solely for a missing conventional address document; **origin/ancestry never affects** ordinary residency.
- Today's flat config still issues identical credentials; the full suite (now including the new `smoke:*` policy suites) stays **green**.

## 7. Target repo layout (additive, not a rewrite)

```
src/core/
  foundational/  proofing/            # Layer 1 — exists
  residency/                          # exists; + lifecycle.ts (new)
    policy-engine/                    # NEW — evaluator, floor.ts, registry.ts
  evidence/                           # NEW — catalogue + normalization port + refs
  jurisdiction/                       # NEW — generic recursive model
  credentials/ oid4vci/ oid4vp/       # Layer 3 — exists; + typed creds + SD-JWT
  eligibility/                        # NEW — Layer 4; evolves sso scopes
  consent/ audit/ operator/ offline/  # cross-cutting — exists (reused)
  sso/ messaging/                     # exists (reused)
config/
  countries/                          # today's configs keep working
  packs/
    global/                           # SEALED human-rights floor
    countries/ jurisdictions/ programmes/ examples/
scripts/
  policy.ts                           # CLI (offline pack evaluation), + smoke:* suites
```

---

## Product definition

> An open-source, jurisdiction-neutral residency policy and credential platform that lets
> governments configure residency definitions, evidence requirements, assurance levels,
> exceptional pathways, credential rules, and service eligibility — without modifying the
> core software.

Common global engine, one legally approved and digitally signed policy pack per
jurisdiction. Nigeria is the first worked example; the model owes nothing to it.
