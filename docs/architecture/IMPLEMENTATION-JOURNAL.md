# ORCS/ORRA implementation tracker

The single record of implementing ORCS-001 v1.0 against this codebase: the baseline it started
from, every finding, what has been built against each, and what remains.

> **Conformance status comes from the build, never from this file.**
>
> ```bash
> npm run conformance:orcs
> ```
>
> It asserts all nine ORCS §15 acceptance criteria and prints PASS / PARTIAL / FAIL with the
> finding id. If this document and that output disagree, the output is right — fix the document.

**Authority:** ORCS-001 v1.0 is normative; ORRA-001 v1.0 is the implementation blueprint
([ADR-0003](../adr/0003-orcs-normative-orra-advisory.md)). Both are circulated separately and
cited by identifier and section, never by committed path.

**Decisions:** `docs/adr/` — [index](../adr/README.md).

---

## Finding status

Fourteen findings, `G-01`…`G-14`. This table is their definition.

| Finding | Subject | State | Phase |
| --- | --- | --- | --- |
| G-01 | Residency is an attribute, not a relationship | ✅ **done by reversal** — `a70e6e4` + `ffb02a2` ([ADR-0004](../adr/0004-one-deployment-one-jurisdiction.md)). `1937c6a`/`8f219f4` built a centralised model and were reverted; multiplicity is federated, so one residency per deployment *is* the answer | — |
| G-02 | `assuranceLevel` unconstrained string | 🟡 partial — fail-open default removed (`0753829`); registry not built | 2 |
| G-03 | No relationship state machine | **reverted** — shipped at `1937c6a`, removed with the centralised design. Returns with relationship lifecycle endpoints | deferred |
| G-04 | No event infrastructure | not started | 4 |
| G-05 | No identity link lifecycle | not started | 2 |
| G-06 | No conflict detection | not started — under ADR-0004 conflict is cross-deployment, so it needs the event/exchange layers (G-04), not G-01 | 6 |
| G-07 | Credential lifecycle incomplete | not started | 2 |
| G-08 | **Consent expiry never enforced** | ✅ **done** — `b9505e0` | — |
| G-09 | No Legal Basis Registry | not started | 2 |
| G-10 | Audit omits purpose and legal basis | not started | 4 |
| G-11 | Jurisdiction level vocabulary closed enum | not started | 1 |
| G-12 | Household and Address not entities | not started | 1a |
| G-13 | Policies unsigned and unversioned | not started | 1 |
| G-14 | Tests assert standards, not ORCS criteria | ✅ **substantially closed** — `a176aea` | — |

---

## Baseline at `c71c489`

Measured, not estimated. This is what Phase 0 (ORRA §14) found, and the starting point every
change above is measured against.

**Modules.** 14 framework-agnostic core modules (`src/core/`, no NestJS dependency) and 16
NestJS delivery modules. That separation is an asset for ORRA §3: the core tree is already the
extraction boundary, so component split-out is packaging rather than rewrite.

**Database — 12 models.** `Resident` (26 fields) conflates five extractable ORCS entities plus
the relationship it keeps. Absent entirely: `Person`, `Jurisdiction`, `Household`, `Address`,
`Evidence`, `AssuranceProfile`, `LegalBasis`, `IdentityLink`, `Service`, `Event`.

**API — 34 operations**, across `operator` (8), `oid4vci` (7), `residency` (5), `consent` (3),
`identity`/`admin`/`audit`/`offline`/`statistics` (2 each), `sso` (1). **Zero** of ORCS's
required endpoints exist: `/persons/{id}/consents`, `/legal-bases/{id}`,
`/legal-bases/{id}/deactivate`, and every identity-link, conflict and event operation.

**Tests.** 13 suites gated in CI, plus a typecheck, a full-stack Postgres end-to-end run and a
container build. Four suites existed but were **ungated** (`smoke:operator`, `smoke:hsm`,
`smoke:gcpkms`, `smoke:awskms`) — 136 assertions CI was not running, closed at `ec9d71d`.

**Integrations.** Six foundational adapters (`nin`, `aadhaar`, `generic-rest`, `generic-xml`,
`dataset-file`, `mock`) behind one registry, plus HSM/AWS-KMS/GCP-KMS signers, pluggable
messaging, a bring-your-own biometric authority, and cross-issuer federation. This already
satisfies ORCS §2 ("identity is consumed") and §16 (Nigeria as a profile, not the model).

**Events.** None. No registry, broker, subscriptions, envelope or delivery semantics. The
nearest analogue is `AuditEvent`, an append-only hash-chained *internal integrity record* — it
carries `eventId`, `timestamp`, `countryCode` and an untyped `target`, and is missing every
routing field in the ORRA §8.1 envelope. It should **not** be retrofitted into a publishable
event: ORCS §14 requires audit to stay tamper-evident, and overloading it with routing puts
that at risk.

### `Resident` maps onto ORCS §4

| `Resident` fields | ORCS entity |
| --- | --- |
| `id`, `fullName`, `givenName`, `familyName`, `dateOfBirth`, `gender`, `phoneHash`, `phoneEnc` | **Person** (§4.1) |
| `subjectRef`, `providerCode`, `bindingMethod`, `bindingRef`, `bindingAt`, `bindingScore` | **IdentityBinding** (§3) |
| `countryCode`, `subnationalUnit` | **Jurisdiction** (§4.2) — config-driven, not a registry |
| `residentId`, `provisional`, `statusListIndex`, `createdAt` | **Relationship** (§4.3) — ✅ *is the row itself*. Not extracted and not typed: per ADR-0004 a deployment holds one per person |
| `residenceAssurance`, `residenceMethod`, `residenceUnit`, `residenceAsOf` | **Evidence** (§4.5) |
| `assuranceLevel`, `residenceAssurance` | **AssuranceProfile** (§8) — currently free strings |
| `credentialId` | **Credential** link (§10) |

The *information* ORCS wants is largely already captured — binding method, binding score,
residence method, residence as-of date. The defect is shape, not substance, which is what makes
the additive migration in [ADR-0006](../adr/0006-additive-migration-resident-facade.md) viable.

### Registry coverage — 1.5 of 11

Consent is closest to complete but missing ORCS §9's controller, processor, `dataCategories`,
evidence of agreement and `legalBasisReference`. Credential has a status list, offline
verification and revocation but is not a registry object. The other nine are absent.

Policy is a partial exception: a jurisdiction-neutral evaluator with a sealed rights floor
exists on the unmerged `docs/residency-policy` branch (`src/core/policy-engine/`, 395 lines,
core-only, no HTTP surface). Not on `main`, not wired in.

### Preserve list

ORRA §15 forbids deleting working behaviour without a documented migration replacing it. These
carry CI-gated conformance and must not regress:

- **PRESERVE** — `src/core/credentials/*` (W3C VC 2.0, VC-JWT, EdDSA/Ed25519, status list);
  `src/core/offline/*`; `src/core/audit/*` (hash chain); `src/sso/*` (pairwise subjects);
  `src/core/foundational/*` (six adapters); `src/core/statistics/*`.
- **EXTEND** — `src/core/residency/*`; `src/core/consent/*` (ORCS §9 fields);
  `src/core/proofing/*` (Evidence entity).
- **ADAPT** — `prisma/schema.prisma` (`Resident` as write-through facade, ADR-0006);
  `src/core/config/country-config.ts` (jurisdiction registry).
- **DEPRECATE-LATER** — no deletions in Phase 1.

---

## What has been built

### ✅ G-01 — Residency, and the reversal that settled it

> **The most instructive thing in this project.** The finding was implemented, committed, and
> reversed within a day. Both halves are kept because the reversal is the lesson.

**First reading (`1937c6a`, `8f219f4`, reverted).** `subjectRef @unique` was taken to encode
"one person, one residency", making ORCS §4.4 unrepresentable. Uniqueness was replaced with the
composite `(subjectRef, providerCode, subnationalUnit, purposeCode)`, and `relationshipType` /
`purposeCode` / `status` were added to the record.

**Why that was wrong.** A deployment is ONE subnational government. ORCS §4.4's person holds
three relationships across three deployments, and Katsina's instance *verifies the credential
Kano issued* rather than holding a Kano row. An instance holding another jurisdiction's
relationships asserts authority ORCS §1.2 explicitly denies it. The unique constraint is the
duplicate-enrolment guard, and it stays. Recorded as
[ADR-0004](../adr/0004-one-deployment-one-jurisdiction.md); the composite key, the relationship
columns and `src/core/residency/relationship.ts` were all removed with it.

**Criterion 1 now asserts the federated reading:** one residency issued per deployment with
re-enrolment idempotent, *plus* a peer jurisdiction's credential verifying and being attributed
to the peer rather than absorbed.

**Three false greens caught along the way**, each of which would have reported a capability the
system did not have:

1. `InMemoryStore.save()` keyed on `subjectRef` alone, so a second record overwrote the first —
   the store disagreed with its own `list()` about how many records existed.
2. The conformance check hand-built records and saved them **straight to the store**, proving
   the model could *hold* concurrent relationships but not that anything could *create* them.
   Issuing one person into three jurisdictions returned `issued, exists, exists` — one record.
   Corrected to PARTIAL at `5f6dc91`.
3. The Prisma write did not set the new columns, so a service that had decided
   `EVIDENCE_PENDING` would have landed the row `ACTIVE` via the column default — a decision
   silently upgraded by a default.

**The generalisable rule:** structural assertions prove a constraint is gone; only end-to-end
assertions prove a capability exists. And any defaulted column must be set explicitly by the
write path, or the default silently overrides a decision already taken.

**Deferred, not rejected:** the ORCS §6.2 lifecycle (nine states, guarded transitions, SUSPENDED
deliberately not live for claim release). It earns its place when relationship lifecycle
endpoints exist — submit, review, suspend, reinstate — rather than sitting unused on a table
whose rows have only one kind.

### ✅ G-08 — Consent expiry enforced · `b9505e0`

The only finding that was a **live defect** rather than a conformance gap. The Phase 0 audit
graded consent "partial — states exist" without checking whether expiry was ever read. It
wasn't: `expiresAt` was written at `consent.ts:99` and read nowhere, and all three read paths
gated on `status === 'active'` alone. A `validityDays: 30` consent authorised claim release for
ever.

- `isExpired()` — the rule, in one place.
- `findActive` treats a lapsed grant as absent **and** transitions it, so stored state converges
  on first read rather than drifting until a sweep runs.
- `grant()`'s reuse check routed through `findActive`. **The sharpest edge:** reusing a lapsed
  grant would have resurrected it — a 30-day consent becoming perpetual at the exact moment the
  citizen was asked to consent again.
- `listByResident` reports lapsed grants as expired, without write-back; a list read is the
  wrong place to take a write.
- `expireDue(residentId)` for deliberate reconciliation (subject-access request, export).
- The receipt carries expiry as a claim **and** as JWT `exp`, so any verifier enforces it.

**Deliberate:** stores do *not* duplicate the predicate. A store filtering expired rows out
would hide them from the service, which could then never transition them — rows sitting
`'active'` for ever while behaving as expired. A harder bug to find.

**Deferred:** no scheduled global sweep. `CONSENT.EXPIRED` has nowhere to go until G-04.

11 assertions in `npm run smoke`; mutation-checked — restoring the old `findActive` fails 3,
including resurrection.

### ✅ G-14 — ORCS criteria machine-checked · `a176aea`

`scripts/orcs-conformance.ts`, run by `npm run conformance:orcs`. Asserts all nine criteria,
each non-passing one tagged with its finding id.

**Red on purpose, and deliberately not in `npm test` or CI.** A permanently-failing required
check trains people to ignore failing checks. It becomes a gate — exit non-zero on any
non-PASS — when the migration completes.

Criterion 5 was softened to match the code: `StatusList.toCredentialSubject` already accepts a
`'suspension'` purpose. What is missing sits above it — only a revocation list is published and
no suspend/reinstate operation exists. SUSPENDED is representable but unreachable, a smaller
gap than "no suspension support".

### ✅ Federation — peer status lists synced · `ac0363d`

The other half of the deployment model. `federatedIssuerSchema.statusListUrl` was parsed, typed
and documented with promised behaviour — and **nothing read it**. A peer's revocation could
never be checked, not "when stale", *ever*.

One omission, two opposite failures:

| Path | Behaviour | Result |
| --- | --- | --- |
| Offline VC | no list → `checkedRevocation: false`, `valid: true` | **revoked** peer credential accepted |
| OpenID4VP | fails closed on that flag (`vp-verifier.ts:164`) | **valid** peer credential refused |

`smoke:federation` was green because it only exercised the fail-open path.
`syncFederatedStatusLists()` now fetches each peer's published credential, parses
`credentialSubject.encodedList`, and caches it by published URL. Fetcher injected, so the suite
stays hermetic and an air-gapped deployment can supply its own transport. Unreachable peers are
logged and skipped, leaving the safe posture. Twelve assertions, mutation-checked.

### DPG track (independent of the migration)

| Commit | Work |
| --- | --- |
| `f4658d7` | Non-PII aggregate statistics export, JSON + RFC 4180 CSV, small-cell suppression with complementary and grand-total suppression. DPG indicator 6; also ORCS §14 portability. |
| `c71c489` | `DPG.md` consolidated as single source of truth; dead links cleared. |
| `ec9d71d` | Gated four ungated suites — **136 assertions CI was not running**. Dependabot, CodeQL, CycloneDX SBOM (628 components), `CODE_OF_CONDUCT.md`. |
| `209ebaf` | ADRs 0003–0006 and `CLAUDE.md` committed. |

**Open debt from `ec9d71d`:** the `npm audit` gate sits at `critical`, not `high`. Four
semver-major upgrades are needed to raise it — `@nestjs/cli@11`, `@nestjs/config@4`,
`@nestjs/platform-express@11`, then `jsonld@9` (last; it processes credential contexts and needs
the full conformance suite re-run). Stated openly in `DPG.md` indicator 8.

---

## Remaining work

Dependency-ordered. Phase 1 prerequisites are complete: ADR-0003 (authority) and ADR-0006
(additive migration) are written and accepted.

| Phase | Work | Closes |
| --- | --- | --- |
| 1a | Additive schema: `Person`, `IdentityBinding`, `Jurisdiction`, `Address`, `Household`, `Evidence`, `PolicyVersion`, `AssuranceProfile`, with `Resident` retained as the write-through facade (ADR-0006). **Not** `JurisdictionalRelationship` — per ADR-0004 the `Resident` row *is* the relationship | G-12, G-13 |
| 1 | Open the jurisdiction `level` vocabulary; add `purpose` and `legalBasisReference` to `AuditEvent` | G-11, G-10 |
| 2 | **Assurance Registry** — canonical profiles across ORCS §8's five dimensions, per-provider mappings with version, issuer, method, limitations. Map `RAL*`→`EA1–3` and `bindingMethod`→`IAL1–3` rather than replacing them | **Criterion 3**, G-02 |
| 2 | **Legal Basis Registry** + `GET /legal-bases/{id}`, `POST /legal-bases/{id}/deactivate`; extend `ConsentRecord` with controller, processor, `dataCategories`, evidence of agreement, `legalBasisReference` | **Criterion 4**, G-09 |
| 2 | **Identity Link Registry** — LINK / UNLINK / RELINK / MERGE / SPLIT / DISPUTE, append-only, no hard deletes | **Criterion 6**, G-05 |
| 2 | Credential suspension + `supersededBy` + revocation reason, authority and appeal path | **Criterion 5**, G-07 |
| 4 | **Event registry + ORRA §8.1 envelope**, alongside — never inside — the audit hash chain. Exchange gateway enforcing purpose, legal basis and consent at delivery | **Criterion 8**, G-04 |
| 6 | **Conflict detection + adjudication.** Note ORCS §7: concurrent relationships are *not* conflicts. Under ADR-0004 this is cross-deployment, so it depends on Phase 4 | **Criterion 2**, G-06 |

Phase 2 items are independent of each other and can proceed in parallel.

Pending ADRs: assurance profile registry; jurisdiction as registry vs. YAML config; event
architecture kept separate from the audit hash chain.

## Open questions

- `package.json` carries the wrong repository URL (`harmonizedx/openresidency`; actual is
  `Harmonizedx/open-residency`) in `homepage`, `repository` and `bugs`. Fix?
- Wire `conformance:orcs` into CI as a **no-regression** gate — failing only if a criterion goes
  backwards — rather than waiting for all-PASS?