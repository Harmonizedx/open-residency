# Releasing OpenResidency

What a release of this project *is*, what it promises, and the checklist for cutting one.

[`docs/PUBLISHING.md`](docs/PUBLISHING.md) covers the one-time mechanics — the public
repository, the npm organisation, submitting to the DPG Registry. This document covers the
recurring policy: versioning, what a release contains, and what an adopter can rely on.

## Versioning

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), with the pre-1.0 rules stated
explicitly because `0.x` means different things to different projects:

| Bump | While `0.x` | After `1.0.0` |
| --- | --- | --- |
| **Major** | reserved for `1.0.0` | breaking change |
| **Minor** (`0.MINOR.0`) | **may break** behaviour an adopter depends on — API shape, config schema, credential contents, database schema | new capability, backwards compatible |
| **Patch** (`0.x.PATCH`) | never breaks | never breaks |

Breaking changes while `0.x` must still be announced in the changelog under **Changed** or
**Removed**, with the migration named. "May break" is permission to change, not permission to
change silently.

### When `1.0.0` is cut

**When a jurisdiction is running this in production, issuing credentials to real residents —
not before.** `1.0.0` is a statement that the interfaces are stable enough for someone to build
against for years. Nothing in a test suite establishes that; only an operator depending on it
does. Declaring `1.0.0` on the strength of a green build would be the same category of
overclaim this project corrects elsewhere.

## What a release is

**A signed, annotated git tag, `vMAJOR.MINOR.PATCH`.** Never a branch, never a moving pointer.
An adopter, an auditor and a DPG reviewer must be able to name the exact tree they assessed.

Pushing the tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which
attaches to the GitHub release:

- **A CycloneDX SBOM**, generated from the installed tree rather than the manifest, so it
  records the versions actually resolved.
- **A source archive** and **`SHA256SUMS`**.
- **Sigstore/cosign signatures**, keyless. There is no private key to store, rotate or leak: the
  signature binds to the workflow's OIDC identity, so a verifier checks *"produced by this
  repository's release workflow"* rather than *"signed by whoever held a secret"*.
- **Build provenance attestations.**
- **The container image**, `ghcr.io/harmonizedx/open-residency:vX.Y.Z`, built from the tag,
  scanned before it is pushed, signed by digest with the same keyless identity, with build
  provenance and an SBOM attested in the registry. The release notes name the digest. Version
  tags only: there is no `latest`, because a release is never a moving pointer, and the
  manifests in `deploy/` pin a version for the same reason.
- **The SDK**, `@openresidency/sdk`, published to npm through trusted publishing: the
  registry checks the workflow's OIDC identity rather than a stored token, and records
  provenance naming the commit and run that built it. The release notes name the version.

## Cadence

Tag on meaningful capability, not on the calendar. This repository moves fast — more than
twenty merges in three days is normal — so a fixed weekly cadence would produce releases nobody
asked for, and a quarterly one would leave adopters pinning a commit hash.

Cut a release when: a capability an adopter is waiting on lands, a security fix ships, or a
deployment needs a citable version.

## Release checklist

Everything below is verified by running it. Do not take any of it from a document, including
this one.

1. **`main` is green.** `npm test` — all suites, zero failures, zero skips. `npm run typecheck`.
   `npm run build`.
2. **Regenerate the Prisma client first** if the schema has changed: `npx prisma generate`. A
   stale client produces dozens of misleading `Property does not exist on PrismaService` errors
   that look like broken code and are not.
3. **Know the conformance position.** Run `npm run conformance:orcs`. All nine passing is
   **not** a release requirement — an honest count is. The release workflow runs the suite
   against the tagged tree and ships the verbatim output as a signed asset
   (`ORCS-CONFORMANCE.txt`) and in the release notes, so it cannot be pasted from the tracker
   or from a previous release. Running it here is so nothing in the result surprises you.
4. **`npm run conformance:mosip`** passes. It gates the build and exits non-zero on any non-PASS.
5. **No known unfixed high-severity advisory.** `npm audit` at the CI gate's level.
6. **CHANGELOG updated.** Move `[Unreleased]` into the new version with today's date. Every
   entry names what an adopter would notice, not what the diff touched.
7. **Version bumped** in `package.json` and `sdk/package.json`, matching the tag.
8. **Tag and push.**
   ```bash
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
   The tag is signed; this repository signs its commits and its tags are no exception.
9. **Verify the release workflow succeeded** — both jobs — and that the SBOM, checksums,
   signatures and provenance are attached, and the release notes carry the image digest. A
   release whose artifacts silently failed to attach is worse than no release, because it looks
   complete.
10. **Verify one file signature and the image signature yourself** before announcing. The
    workflow emits a `.sig` and a `.pem` per asset, not a bundle:
    ```bash
    cosign verify-blob SHA256SUMS --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
      --certificate-identity-regexp '^https://github.com/Harmonizedx/open-residency/\.github/workflows/release\.yml@' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    cosign verify ghcr.io/harmonizedx/open-residency@sha256:<digest from the release notes> \
      --certificate-identity-regexp '^https://github.com/Harmonizedx/open-residency/\.github/workflows/release\.yml@' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    ```
11. **First release only: make the package public.** A container package created by a
    workflow is private until someone changes it — GHCR does not inherit the repository's
    visibility. Repository → Packages → `open-residency` → Package settings → Change
    visibility → Public. Then `docker pull` it from a machine with no GitHub credentials to
    confirm.
12. **Confirm the SDK landed.** The `sdk` job publishes it through npm trusted publishing
    and refuses when `sdk/package.json` does not match the tag, so a failure here is step 7
    skipped. The registry lags the publish by a minute or so.
    ```bash
    npm view @openresidency/sdk version
    ```
    If the job could not publish, the manual fallback is in `docs/PUBLISHING.md`.

## Security releases

- Only the **latest minor** receives security fixes while the project is `0.x`. Maintaining
  branches nobody runs costs more than it protects. This changes at `1.0.0`.
- A security release is a patch bump, cut as soon as a fix is available, and does not wait for
  unrelated work.
- Disclosure follows [`SECURITY.md`](SECURITY.md): coordinated, with the fix published before
  the detail.
- The changelog entry says what was possible before the fix. An entry that says only "hardening"
  denies a deploying government the information it needs to judge urgency.

## Deprecation

At least one minor version of notice before removal, announced in the changelog under
**Deprecated**, naming the replacement. Config keys and API fields are removed only after that
notice, and never in a patch.

## What a release does not claim

- **Not a conformance certificate.** ORCS §15 is a sample of the specification, not an audit of
  it. Say "all nine §15 criteria pass" if they do; never "ORCS-conformant".
- **Not MOSIP certification, compliance or partnership.**
- **Not a production endorsement.** The issuer key, the pepper, the aggregator contract and the
  legal basis are the deploying jurisdiction's to complete — see the caveats in the README and
  `docs/DPG.md`.
