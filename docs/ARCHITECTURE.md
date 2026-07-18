# Architecture

OpenResidency is built as a small framework-agnostic core with thin NestJS delivery
around it. This split is deliberate: the core carries the identity, credential,
consent, and audit logic with no web framework, so it is unit-testable (see the smoke
test) and embeddable as a library, while NestJS only handles HTTP, wiring, and
persistence adapters.

## Layers

```
                 +--------------------------------------------------+
   HTTP / OIDC   |  NestJS controllers, guards, OIDC provider mount |
                 +--------------------------------------------------+
                                     |
                 +--------------------------------------------------+
   Core (no fw)  |  foundational | residency | credentials | offline|
                 |  consent      | audit                            |
                 +--------------------------------------------------+
                                     |
                 +--------------------------------------------------+
   Ports         |  ResidencyStore | ConsentStore | AuditStore      |
                 +--------------------------------------------------+
                          |                         |
                 InMemory* (tests/pilots)    Prisma* (PostgreSQL)
```

## Component map

| Concern | Core | Delivery |
|---|---|---|
| Identity Verification API | `foundational/*`, `residency/residency-service#getProvider` | `identity/identity.controller.ts` |
| Resident Registry | `residency/ports.ts` | `prisma/prisma.service.ts`, `admin/admin.controller.ts` |
| Residency Verification API | `credentials/vc-verifier.ts` | `residency/residency.controller.ts` |
| State SSO | `sso/oidc.provider.ts` | `sso/oidc.module.ts`, `sso/interaction.controller.ts` |
| Consent Framework | `consent/consent.ts` | `consent/consent.controller.ts` |
| Audit Framework | `audit/audit-log.ts` | `audit/audit.controller.ts` |
| API Gateway posture | `common/api-key.guard.ts`, throttler in `app.module.ts` | `deploy/k8s/ingress.yaml` |
| Interoperability SDK | (client) | `sdk/` |
| Reference UI | (client) | `public/` served at `/app` |
| API specifications | `docs/openapi.yaml` | `meta/meta.controller.ts` (`/openapi.yaml`, `/docs`) |

## Data flow: enroll to SSO

1. Citizen submits foundational identifiers. The foundational adapter verifies against
   the national ID API and returns a NormalizedIdentity with a tokenized `subjectRef`.
   The raw national ID never leaves the adapter. This step establishes that the identity
   **record** is genuine — it does not, on its own, establish that the applicant **owns**
   it.
2. ResidencyService establishes applicant→identity binding: it combines any binding the
   provider attested (an OTP to the registered device, an eID redirect →
   `authoritative_authentication`) with any the enrolment channel performed (an agent's
   in-person comparison, a face/fingerprint match), takes the strongest, and holds it to
   the jurisdiction's `residency.applicantBinding` policy. A bare lookup binds nothing, so
   a policy with `required: true` refuses to issue on a lookup alone. See
   `core/proofing/binding.ts`.
3. ResidencyService enforces the assurance policy, mints a ResidentID, issues a signed
   VC-JWT that **asserts the binding method** in `credentialSubject.applicantBinding`,
   assigns a revocation index, and persists a minimized record. An audit event records
   which binding method was achieved.
4. A sector service verifies the credential (online or fully offline) via the verifier.
5. For SSO, the citizen signs in once at the OIDC provider. On consent, a first-class
   ConsentRecord is stored, a signed receipt is minted, and an audit event is recorded.
   The ID token carries residency claims but never the national ID.

## Why these standards

Ed25519 VC-JWT keeps credentials small enough for a single QR and paper carriage, and
verifiable with one signature check offline. The Bitstring Status List lets verifiers
cache revocation and check it without a callback. OpenID Connect means any conformant
relying party integrates without bespoke work. The audit log is hash-chained so it is
tamper-evident, which is the property public-infrastructure oversight requires.
