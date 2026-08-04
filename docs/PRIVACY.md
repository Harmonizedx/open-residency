# Data protection

How OpenResidency handles personal data, what a deployer must decide, and what the software
enforces on their behalf.

This is a statement about **the software**. A deployment is a data controller in its own
right: the Katsina State Residency Authority, not this repository, decides lawful basis,
retention periods and disclosure policy. What follows describes what the software does, so a
controller can write their own notice on top of it without reverse-engineering the code.

Written against the six privacy requirements the Digital Public Goods Alliance added to the
DPG Standard in 2024, and ORCS §14.

## 1. What is collected, and what is deliberately not

| Held | Notes |
| --- | --- |
| A tokenized `subjectRef` | HMAC of provider + national ID under a per-deployment pepper. One-way, and not correlatable with another deployment's reference for the same person. |
| `residentId` | Pseudonymous, semi-public by design — printed on cards, carried in QR codes. |
| Minimized demographics | Name, date of birth, gender — only what the credential asserts. |
| Jurisdiction, assurance, binding method, residence evidence level | The decision inputs, so a determination can be explained. |
| Phone number | Only when `contactDirectory.mode` is `encrypted`: AES-256-GCM ciphertext under a key held outside the database, plus a one-way hash for matching. Under `external` or `none`, only the hash. |

**Never held:** the raw national identification number. It reaches the foundational adapter,
is tokenized, and does not survive the call. It is never stored, never logged, never returned
in a response, and never placed in a credential or an SSO claim.

## 2. Data minimisation

Enforced structurally rather than by policy. The aggregate statistics export
(`src/core/statistics/*`) consumes a projection type that has no name, date-of-birth, gender,
contact, `residentId` or `subjectRef` field on it, so a personal attribute cannot reach a
published statistic — there is one narrowing point to review rather than a rule to remember.
Contact details are deliberately kept off the residency port entirely, so the core residency
service has no capability to touch a phone number.

## 3. Consent

Consent is a first-class, revocable record with a signed, portable receipt the citizen keeps.
Grant, inspect, withdraw, expire and audit are all supported.

**Expiry is enforced, not merely recorded.** A consent granted with a validity period stops
authorising disclosure the moment it lapses, on every read path, and the stored record
converges to `expired` rather than sitting `active` while behaving otherwise. Withdrawal also
revokes the OIDC grant it authorised, so tokens already issued stop releasing claims.

Consent is one lawful basis among several. Where a deployment processes under statutory
authority instead, that is a different basis and must be recorded as such — see the gap in §8.

## 4. Erasure

`POST /residency/{residentId}/erase` (operator, `admin` role).

Erasure and a tamper-evident register pull in opposite directions: the citizen may require
their data destroyed, and the register must be able to show nothing was quietly rewritten.
Deleting rows satisfies the first and destroys the second. The resolution is that erasure
removes **the person**, not the record that a transaction occurred:

1. **The credential is revoked first.** Order matters — erasing first would leave a credential
   in a wallet that still verifies against a register no longer able to say whose it is.
2. **Every identifying field is destroyed**: names, date of birth, gender, phone hash and
   ciphertext, and the `subjectRef` linking the record to a foundational identity. The
   `subjectRef` is overwritten with a unique random tombstone, so the record can never again
   match a lookup and the same person re-enrolling is correctly treated as new.
3. **Audit events naming the subject are redacted, not deleted.** The rows and their hashes
   remain, the plaintext goes, and each redaction is appended as its own chained event naming
   who performed it, why, and under what legal basis.

**The audit chain still verifies after erasure**, and reports how many events were redacted
rather than concealing it. A redacted event's stored hash still commits to its original
content, so anyone holding an earlier copy of the log can prove what it said. Editing an event
*without* redacting it is still detected as tampering.

### What survives, and why

A hollow row remains, carrying `residentId`, `statusListIndex` and `erasedAt`. Each is kept
for a specific reason, and dropping any of them would be a defect:

- **`statusListIndex` must never be reused.** Reissuing an erased person's index would hand
  their revocation bit to the next resident enrolled.
- **The credential must stay revoked.** A revocation whose record is deleted is a revocation
  that can be forgotten.
- **`residentId` appears in chained audit events.** Removing it there is redaction, not
  deletion, for the integrity reason above.

What remains is an opaque identifier with no name, no contact, no link to a national ID, and a
revoked credential. A controller who wants the row gone entirely may delete it once its
retention period has expired **and** the status list has been rotated — a deliberate,
documented operation, never a default.

## 5. Retention

Retention is per record class, because an audit entry, a consent grant and a residency record
are kept under different bases for different reasons; one global number fits none of them.

| Class | Measured from |
| --- | --- |
| Residency records | Creation |
| Consent records | Grant. Withdrawal does not shorten it — proof that consent was given and withdrawn is itself a record a controller may need. |
| Audit events | Event timestamp |

**The shipped default expires nothing.** Retention is a decision a controller makes against
their own law, and a default period would be this repository quietly setting policy for a
government. `null` means no automatic expiry and must be chosen deliberately.

A **legal hold** suspends every period. When set, the sweep refuses to run at all rather than
reasoning about which records an open appeal or a regulator's request might implicate —
deleting the evidence an appeal turns on is the failure this prevents.

## 6. Access control and audit

Role-scoped operator identity with per-operator API keys and rotation; privileged reads are
attributed to a named person, not a shared key. Every privileged action is recorded in an
append-only, hash-chained log. Erasure requires `admin` — a stricter role than revocation,
because a caller who can erase can also destroy evidence of their own earlier actions, which
is why the redaction record names them.

## 7. Subject rights

| Right | Mechanism |
| --- | --- |
| Access | `GET /consent/resident/{residentId}`, `GET /residency/{residentId}` |
| Portability | Consent receipts are signed, portable JWTs the citizen holds; the credential itself is a portable W3C VC |
| Erasure | `POST /residency/{residentId}/erase` |
| Withdraw consent | `POST /consent/{id}/revoke` — blocks future consent-dependent disclosure and revokes the associated OIDC grant |

## 8. Known gaps

Stated because a privacy notice that omits them is worth less than one that does not.

- **No Legal Basis Registry.** Every disclosure should resolve to a registered, versioned
  legal basis; today `purpose` is free text on the consent record and statutory bases are not
  modelled. Tracked as G-09.
- **Audit events do not carry purpose or legal basis.** Tracked as G-10.
- **Assurance values are not governed.** `assuranceLevel` is a bare string from a fixed
  vocabulary with no registry to resolve it against. It is released over SSO, so relying
  parties should gate on the standard `acr` claim instead. Tracked as G-02.
- **No automated retention sweep is wired to a scheduler.** The policy and the selection logic
  exist and are tested; running them on a schedule is a deployment decision.

## 9. What a deployer must complete

- A Data Protection Impact Assessment against governing law (for Nigeria, the Nigeria Data
  Protection Act) and a record of processing activities. Templates: `docs/templates/`.
- Retention periods for each class in §5, and who may set a legal hold.
- The lawful basis for the foundational-identity check, agreed with the identity authority.
- A published privacy notice for residents, which may cite this document but should not
  substitute for it — this describes software, not a controller's practice.
- A disclosure review before publishing the aggregate statistics export as open data.