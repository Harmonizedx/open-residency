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

## Verifying what you downloaded

Every tagged release carries a CycloneDX SBOM, a source archive, `SHA256SUMS`, and a
Sigstore signature and certificate for each.

Signing is **keyless**. There is no long-lived private key to store, rotate, or leak: the
signature is bound to the release workflow's OIDC identity, so what you verify is *"this was
produced by this repository's release workflow"* — a stronger and more checkable claim than
"signed by whoever held a secret in repository settings".

```bash
cosign verify-blob sbom.cyclonedx.json \
  --signature sbom.cyclonedx.json.sig \
  --certificate sbom.cyclonedx.json.pem \
  --certificate-identity-regexp 'https://github.com/Harmonizedx/open-residency/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Build provenance is attested separately and can be checked with
`gh attestation verify <file> --repo Harmonizedx/open-residency`. A signature says *who*;
provenance says *how*.

**The container image is not signed**, because it is built in CI and never pushed to a
registry, and cosign signs images by digest in a registry. Publishing images is a separate
decision; until it is taken, build the image yourself from a verified source archive.

### Vulnerability scanning

Dependencies are gated with `npm audit` at moderate, and the built container image is scanned
with Grype at High. Anything waived is recorded in `.grype.yaml` with a reason and a review
date, rather than by raising the threshold until the job passes.

**Dependency overrides.** A transitive advisory with no upstream fix is resolved with an
`overrides` entry in `package.json`, never by loosening the audit threshold. Each one is
recorded here with what it pins, why, and the condition for removing it — an override nobody
can explain is one nobody dares delete.

| Override | Why | Remove when |
| --- | --- | --- |
| `deepmerge-ts: ^8.0.1` | [GHSA-ggr8-5vv4-36mx](https://github.com/advisories/GHSA-ggr8-5vv4-36mx) (high, stack exhaustion). `@prisma/config` pins `deepmerge-ts` to exactly `7.1.5`, and 7.9.1 was the latest Prisma when this landed, so there was no release to upgrade to. `npm audit fix --force` proposed `prisma@6.12.0` — a major downgrade. Reached only through the Prisma **CLI** config loader (`migrate`/`generate`/`validate`), never by the running app. | `@prisma/config` depends on `deepmerge-ts@>=8`. Check on a Prisma minor bump; drop the entry and confirm `npm audit --omit=dev` stays clean. |
