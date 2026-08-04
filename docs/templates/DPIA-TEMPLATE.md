# Data Protection Impact Assessment — template

For a deployment of OpenResidency. Complete before processing real residents' data.

A DPIA assesses **a deployment**, not software. This repository processes nobody's data;
your instance does. Where a row below is already answered by the software's design, the
answer is given so you can verify it rather than write it from scratch — but confirm each
against your own configuration, because most are configurable and some defaults are
deliberately conservative.

Reference: `docs/PRIVACY.md`.

---

## 1. Identification

| Field | Value |
| --- | --- |
| Controller | *e.g. Katsina State Residency Authority* |
| Data Protection Officer | |
| Assessment date / review date | |
| Governing law | *e.g. Nigeria Data Protection Act 2023* |
| Supervisory authority | *e.g. Nigeria Data Protection Commission* |
| Deployment | *jurisdiction, environment, URL* |

## 2. Processing described

| Question | Answer |
| --- | --- |
| Purpose | |
| Lawful basis for residency enrolment | *statute? consent? both, per purpose?* |
| Lawful basis for the foundational-ID check | *must be agreed with the identity authority* |
| Categories of data subject | *residents; minors? displaced persons?* |
| Categories of personal data | See `PRIVACY.md` §1 |
| Special-category data | *biometrics, if a biometric authority is configured* |
| Recipients | *which relying parties, under which scopes* |
| International transfers | *hosting location; any cross-border processor* |
| Retention periods | See `PRIVACY.md` §5 — **the default expires nothing; you must set these** |

## 3. Necessity and proportionality

- Why is each attribute in §2 necessary for the stated purpose?
- What is the least identifying alternative considered, and why was it rejected?
- How is the raw national ID kept out of the system? *(Software: tokenized at the adapter,
  never stored, logged or returned. Confirm your adapter configuration.)*

## 4. Risks

Assess each. The first four are inherent to residency infrastructure; the rest depend on
configuration.

| # | Risk | Inherent | Mitigation | Residual |
| --- | --- | --- | --- | --- |
| 1 | **Exclusion** — a person unable to enrol loses service access | | Offline verification, USSD for feature phones, multiple evidence routes so no single document is mandatory | |
| 2 | **Discrimination** — residency conditioned on origin, indigene status or ethnicity | | Prohibited by `CODE_OF_CONDUCT.md`; origin is recorded separately from residence and never as an eligibility input | |
| 3 | **Function creep** — the register used for purposes never assessed | | Per-relying-party scopes; consent records; this DPIA must be revised before a new purpose | |
| 4 | **Correlation across services** — two agencies joining records on a shared identifier | | Pairwise SSO subjects; `resident_id` released only to relying parties with a lawful basis | |
| 5 | **Re-identification from published statistics** | | Small-cell suppression, complementary suppression, withheld grand total — see `docs/API.md`. **Conduct a disclosure review before publishing.** | |
| 6 | **Insider access** | | Per-operator identity and keys, role scoping, audited reads | |
| 7 | **Issuer key compromise** | | HSM/KMS custody; rotation and revocation procedures | |
| 8 | **Credential theft or replay** | | Holder binding, short validity, revocation via status list | |
| 9 | **Contact data exposure** | | Encrypted at rest under a key outside the database; hash-only if `contactDirectory.mode` is `external`/`none` | |
| 10 | **Erasure defeated by backups** | | **Your procedure.** The software erases the live record; restoring an old backup reinstates it. State how backups are aged out or re-erased. | |

## 5. Subject rights

| Right | How exercised here | Your process |
| --- | --- | --- |
| Access | `GET /residency/{id}`, `GET /consent/resident/{id}` | |
| Erasure | `POST /residency/{id}/erase` | |
| Withdraw consent | `POST /consent/{id}/revoke` | |
| Portability | Signed consent receipts; the credential is a portable W3C VC | |
| Object / appeal | **Not implemented in software.** Define an administrative route. | |

## 6. Decisions

| | |
| --- | --- |
| Residual risk accepted by | *name, role* |
| Date | |
| Conditions of approval | |
| Next review | |

## 7. Sign-off

Do not sign until §2 retention periods are set, risk 10 (backups) has a stated procedure, and
the erasure route in §5 has been tested end to end on this deployment.
