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
  `exists`, `challenge`, or `rejected`.
- `GET /residency/{residentId}` — non-sensitive residency status.
- `POST /residency/verify` — verify a presented VC-JWT (signature, expiry, revocation).
- `POST /residency/revoke/{residentId}` — revoke a credential.

## Consent

- `GET /consent/resident/{residentId}` — list a resident's consents.
- `POST /consent/grant` — grant consent and receive a signed receipt (also happens
  automatically during the SSO consent step).
- `POST /consent/{id}/revoke` — withdraw a consent.

## Audit and admin (require `x-admin-key`)

- `GET /audit` — read the audit log (newest first).
- `GET /audit/verify` — confirm the hash chain is intact.
- `GET /admin/residents` — list registry entries.
- `GET /admin/stats` — counts by country.

## Offline

- `POST /offline/qr` — render a credential as an SVG QR.
- `POST /offline/ussd` — USSD webhook for feature phones.

## SSO

- OIDC discovery: `GET /oidc/.well-known/openid-configuration`.
- Interaction (login/consent) pages under `/interaction/*`.
- Issuer DID document: `GET /.well-known/did.json`.

## Auth model

Public endpoints are open in this reference build. `/admin` and `/audit` require the
admin key via `x-admin-key` or `Authorization: Bearer <key>`. In production, put
citizen-facing consent routes behind the same OIDC login, and keep admin behind the
key plus edge restrictions (see `deploy/k8s/ingress.yaml`).
