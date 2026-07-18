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

## Audit and admin (require `x-admin-key`)

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
`.well-known` documents, credential verification) are open. Privileged routes require
the admin key via `x-admin-key` or `Authorization: Bearer <key>`: `/admin`, `/audit`,
`/consent`, the VC-API, credential-offer and presentation-request creation, and both
residency issuance and revocation. `POST /offline/ussd` takes a separate gateway secret.

Two known limits of this reference build, both on the path to a production deployment:

- The admin key is a single shared static secret. There is no per-operator identity, so
  every privileged action audits to the same actor, and there are no roles and no
  rotation. Replace it with operator SSO (OIDC-protected admin scopes or mTLS) before
  government staff use it.
- The OIDC `sub` is the resident id, identical across every relying party — see
  `INTEGRATION.md` on pairwise identifiers.

In production, also put citizen-facing consent routes behind the OIDC login and keep
admin behind edge restrictions (see `deploy/k8s/ingress.yaml`).
