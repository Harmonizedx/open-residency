# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities.

Report privately through the security contact published on the HarmonizedX website, or
by opening a GitHub security advisory on this repository. Include a description, steps
to reproduce, and the impact you observed. We aim to acknowledge reports within a few
business days.

## Scope and sensitive areas

OpenResidency handles identity and residency data. Please pay particular attention to,
and report responsibly, issues in:

- The foundational adapter layer (any path where a raw national ID could leak or be
  logged, persisted, or returned).
- Credential issuance and verification (signature, expiry, revocation bypass).
- The SSO authentication factor and consent flows.
- The audit log (any way to append, edit, or delete without breaking the hash chain).
- The admin and audit endpoints and their authentication.

## Handling and disclosure

We follow coordinated disclosure. Once a fix is available we will publish a release and
credit the reporter unless anonymity is requested. Deployers should watch releases and
apply security updates promptly, especially any affecting credential verification or the
issuer key.

## Deployer responsibilities

This is infrastructure you self-host. You are responsible for KMS custody of the issuer
key, a real SSO authentication factor, TLS, network controls, database security, and a
data protection impact assessment for your jurisdiction. See `README.md` caveats and
`docs/DEPLOY.md`.
