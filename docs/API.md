# API reference

The authoritative, machine-readable spec is `docs/openapi.yaml`. When the server runs
it is served at `/openapi.yaml` and browsable at `/docs` (Swagger UI). This page is a
quick orientation.

## Identity Verification

- `POST /identity/challenge` — start an OTP for two-step providers (e.g. Aadhaar).
- `POST /identity/verify` — verify a person against the foundational ID and return
  minimized attributes plus assurance. No residency is issued and nothing is stored.

## Residency

- `GET /residency/countries` — served countries and the inputs each check needs.
- `POST /residency/issue` — verify then issue a residency VC. Returns `issued`,
  `exists`, `challenge`, or `rejected`. **Requires `x-admin-key`**: it accepts operator
  attestations (`binding`, `residenceEvidence`) that a self-serving caller must not be
  able to assert about themselves.
- `GET /residency/{residentId}` — non-sensitive residency status.
- `POST /residency/verify` — verify a presented VC-JWT (signature, expiry, revocation).
- `POST /residency/revoke/{residentId}` — revoke a credential. **Requires `x-admin-key`.**

## Consent

- `GET /consent/resident/{residentId}` — list a resident's consents.
- `POST /consent/grant` — grant consent and receive a signed receipt (also happens
  automatically during the SSO consent step).
- `POST /consent/{id}/revoke` — withdraw a consent.

## Operator identity

- `POST /operator/login` — local sign-in (password + TOTP) for a short-lived session
  token. Only when `operatorAuth.mode: local`.
- `GET /operator/me` — the calling operator's identity and roles.
- `GET|POST /operator/operators` — list and create operators (`admin`).
- `POST /operator/operators/:id/disable` — disable an account (`admin`).
- `GET|POST /operator/keys` — list and mint per-operator API keys.
- `POST /operator/keys/rotate` — mint a replacement and retire the old key after an
  overlap window, so callers cut over one at a time.
- `POST /operator/keys/revoke` — kill a key immediately.

## Audit and admin (operator-authenticated)

- `GET /audit` — read the audit log (newest first).
- `GET /audit/verify` — confirm the hash chain is intact.
- `GET /admin/residents` — list registry entries.
- `GET /admin/stats` — counts by country.

## Offline

- `POST /offline/qr` — render a credential as an SVG QR.
- `POST /offline/ussd` — USSD webhook for feature phones. **Requires
  `USSD_GATEWAY_SECRET`** as `x-ussd-secret`: the handler trusts the caller's word for
  `phoneNumber`, so only the aggregator may call it.

## SSO

- OIDC discovery: `GET /oidc/.well-known/openid-configuration`.
- Interaction (login/consent) pages under `/interaction/*`.
- Issuer DID document: `GET /.well-known/did.json`.

## Auth model

Endpoints that are public by specification (wallet-facing OpenID4VCI/VP routes,
`.well-known` documents, credential verification) are open. Everything privileged
requires an authenticated **operator**: `/admin`, `/audit`, `/consent`, the VC-API,
credential-offer and presentation-request creation, and both residency issuance and
revocation. `POST /offline/ussd` takes a separate gateway secret.

### How an operator authenticates

Set by `operatorAuth.mode` in the country config:

| Mode | Credential | Notes |
|---|---|---|
| `oidc` | `Authorization: Bearer <IdP access token>` | **Recommended.** Validated against the IdP's JWKS. Staff accounts, MFA and de-provisioning stay in the ministry's directory; this system stores no staff credentials. |
| `local` | `Authorization: Bearer <session token>` from `POST /operator/login` | Accounts in Postgres: scrypt passwords, TOTP, lockout. For deployments with no IdP yet. |
| any | `x-operator-key: ork_...` | Per-operator API key for machine callers. Identified, role-scoped, expiring, rotatable. |
| `sharedKey` | `x-admin-key: <ADMIN_API_KEY>` | **Legacy.** No identity, no roles, no rotation. Warns on every boot. |

### Roles

`@RequireRoles` on each route; `admin` satisfies every check.

| Role | Grants |
|---|---|
| `registrar` | residency issuance, credential offers, VC-API issuance |
| `revoker` | residency revocation |
| `auditor` | the audit log and its chain verification |
| `support` | registry reads, consent administration, presentation requests |
| `admin` | everything, plus operator and key management |

### Correlation

The OIDC `sub` is **pairwise** by default: each relying party sees a different, stable,
unguessable identifier for the same citizen, derived as HMAC(pepper, clientId +
residentId). The `residency` scope — which releases the correlatable `resident_id` — is
no longer granted to every RP automatically; it is opt-in per RP via `scopes` in the
config. Both halves are needed: pairwise subjects alone buy nothing while every service
can still read the same `resident_id`.

In production, also put citizen-facing consent routes behind the OIDC login and keep
admin behind edge restrictions (see `deploy/k8s/ingress.yaml`).
