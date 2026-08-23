# Releasing OpenResidency

What a release of this project *is*, what it promises, and the checklist for cutting one.

[`docs/PUBLISHING.md`](docs/PUBLISHING.md) covers the one-time mechanics — creating the public
repository, publishing the SDK, submitting to the DPG Registry. This document covers the
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

Container images are built in CI but not pushed to a registry. Publishing images is a separate
decision with its own consequences, so the release signs what it actually ships.

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
3. **Record the conformance position.** Run `npm run conformance:orcs` and put the result in the
   release notes verbatim. All nine passing is **not** a release requirement — an honest count
   is. Do not quote a number from the tracker or from a previous release.
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
9. **Verify the release workflow succeeded** and that the SBOM, checksums, signatures and
   provenance are attached. A release whose artifacts silently failed to attach is worse than no
   release, because it looks complete.
10. **Verify one signature yourself** before announcing:
    ```bash
    cosign verify-blob --bundle <asset>.sigstore <asset>
    ```

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
