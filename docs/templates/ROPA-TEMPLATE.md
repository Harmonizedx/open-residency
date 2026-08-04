# Record of Processing Activities — template

A controller's register of what it processes and why. Required alongside a DPIA under most
data protection regimes, including the Nigeria Data Protection Act.

One row per processing activity. The four below are the activities a default OpenResidency
deployment performs; add rows for anything your jurisdiction does on top, and delete any you
do not enable.

Reference: `docs/PRIVACY.md`.

---

## Controller

| Field | Value |
| --- | --- |
| Controller | |
| Contact / DPO | |
| Joint controllers | *the foundational identity authority may be one — confirm* |
| Processors | *hosting, SMS aggregator, KMS provider, biometric authority* |
| Last reviewed | |

---

## Activity 1 — Residency enrolment and credential issuance

| Field | Value |
| --- | --- |
| Purpose | Establish and evidence a person's residency in the jurisdiction |
| Lawful basis | *statute / consent — state which, and cite it* |
| Data subjects | Residents |
| Personal data | Tokenized `subjectRef`; `residentId`; name, date of birth, gender; jurisdiction; assurance level; binding method; residence evidence level |
| Explicitly not held | Raw national identification number |
| Source | The resident, plus the foundational identity authority |
| Recipients | The resident (as a credential); relying parties per scope |
| Transfers | |
| Retention | *set — the software default expires nothing* |
| Security | HMAC tokenization; EdDSA credential signing with HSM/KMS custody; encryption in transit and at rest |

## Activity 2 — Consent management

| Field | Value |
| --- | --- |
| Purpose | Record, evidence and enforce the resident's permission for a relying party to receive claims |
| Lawful basis | Consent; the record itself may be kept under legal obligation |
| Personal data | `residentId`, tokenized `subjectRef`, relying party, purpose, scopes, grant/expiry/withdrawal timestamps |
| Recipients | The resident (signed receipt); auditors |
| Retention | *set — note that withdrawal does not shorten it* |
| Security | Signed receipts; withdrawal revokes the associated OIDC grant |

## Activity 3 — Audit logging

| Field | Value |
| --- | --- |
| Purpose | Demonstrate that privileged actions are attributable and unaltered |
| Lawful basis | Legal obligation / legitimate interest — state which |
| Personal data | `residentId` as target; operator identity as actor; action, outcome, timestamp |
| Recipients | Auditors, oversight bodies |
| Retention | *set* |
| Security | Append-only SHA-256 hash chain. Erasure redacts rather than deletes, preserving verifiability; each redaction is itself recorded |

## Activity 4 — Cross-sector authentication (SSO)

| Field | Value |
| --- | --- |
| Purpose | Let a resident sign in to sector services without re-proving identity |
| Lawful basis | |
| Personal data disclosed | Pairwise subject identifier; residency claims per scope. **Never the national ID** |
| Recipients | Registered relying parties |
| Retention | Session and token lifetimes — *state* |
| Security | OIDC Authorization Code + PKCE; pairwise subjects so two relying parties cannot join records; `resident_id` released only under a scope granted deliberately |

---

## Optional activities — delete if not enabled

| Activity | Enabled? | Notes |
| --- | --- | --- |
| Contact capture for OTP delivery | | Encrypted at rest under a key outside the database, or hash-only |
| Biometric verification | | Special-category data; requires its own basis and a DPIA section |
| Aggregate statistics publication | | Non-personal by construction, but conduct a disclosure review |
| Cross-issuer federation | | Verifying peers' credentials; note whose data is processed and under what arrangement |