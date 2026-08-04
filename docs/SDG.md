# Sustainable Development Goal mapping

OpenResidency maps to one primary Sustainable Development Goal and five supporting ones.
Every mapping below is anchored to a capability that exists in the codebase today — a file,
endpoint, or documented mechanism — rather than an aspiration. This is the authoritative SDG
list; `docs/DPG.md` references it and must stay consistent with it.

## Primary

| SDG | Why it applies | Evidence anchor |
| --- | --- | --- |
| **16.9 — Legal identity for all** | The whole point of the platform: it binds a national/foundational identity to an offline-verifiable W3C State Residency credential and gives subnational populations a usable proof of who and where they are. | `src/core/residency/residency-service.ts`, `src/core/credentials/vc-issuer.ts`, `docs/openapi.yaml` |

## Supporting

| SDG | Why it applies | Evidence anchor |
| --- | --- | --- |
| **1 — No poverty** | A verifiable residency credential plus cross-sector single sign-on lets residents reach subsidy and social-benefit services they would otherwise be excluded from for lack of proof of residence. | `src/core/sso/*`, `src/core/credentials/vc-issuer.ts` |
| **5 — Gender equality** | Gender is an **optional, consent-gated** attribute, not a gate on issuance: it flows only when a foundational source supplies it and is released to a relying party solely under a per-client OIDC consent grant. Non-discrimination is enforced structurally — origin/indigeneity is never admissible as residence evidence (see SDG 10 anchor). | `src/core/residency/ports.ts` (optional `gender`), `src/core/consent/consent.ts` (scoped, revocable consent), `src/core/proofing/residence.ts` |
| **8 — Decent work and economic growth** | The residency credential is the proof residents need to register for tax, obtain permits, and participate in the formal economy. | `src/core/credentials/vc-issuer.ts`, `docs/API.md` |
| **10 — Reduced inequalities** | Inclusion for low-connectivity and feature-phone users via offline QR and USSD paths; and an explicit non-discrimination control — `evaluateResidence` keeps state-of-origin separate from state-of-residence and only ever evaluates residence, so indigeneity/heritage cannot affect the outcome. | `src/core/offline/qr.ts`, `src/core/offline/ussd.ts`, `src/core/proofing/residence.ts` |
| **16 — Peace, justice and strong institutions** | Beyond 16.9: a tamper-evident, hash-chained audit trail and first-class revocable consent with signed receipts make institutional use accountable and auditable. | `src/core/audit/audit-log.ts`, `src/core/consent/consent.ts` |

## Notes

- **SDG 3 (health) is intentionally not claimed.** Health service access is a possible
  downstream use of the credential, but the platform ships no health-specific capability, so
  it is not listed.
- **SDG 5 is not gender-disaggregated statistics.** The non-PII statistics export
  (`src/core/statistics/aggregate.ts`) is aggregate-only and its `StatisticsInput` carries no
  gender field at all, so no gender-disaggregated data can leave the system. The SDG 5 claim
  rests on the consent-gated gender attribute and the non-discrimination controls above, not
  on statistics that do not exist.
