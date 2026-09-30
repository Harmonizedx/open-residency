# Publishing OpenResidency

The one-time mechanics, done with HarmonizedX's accounts. `RELEASING.md` covers the
recurring policy: versioning, what a release contains, and the per-release checklist.

## 1. The public repository

`https://github.com/Harmonizedx/open-residency` is public. CI (`.github/workflows/ci.yml`)
runs on pull request and on push to `main`: typecheck, the smoke suites, the ORCS §15
ratchet, and a Docker image build and scan. The W3C suite needs a running server and stays
opt-in (`npm run test:w3c`). A tag push runs `release.yml`, which
attaches the signed SBOM, source archive and conformance record to the GitHub release and
publishes the signed image to `ghcr.io/harmonizedx/open-residency`. The first release needed
the package made public by hand — see `RELEASING.md`.

If the org handle ever changes, update it in: root `package.json`, `sdk/package.json`, the
image references in `deploy/`, `SECURITY.md`, `RELEASING.md`, `docs/DEPLOY.md`, and the URLs
in `docs/`. The workflow derives the image name from the repository, so it needs no edit.

## 2. The SDK on npm

`@openresidency/sdk` is published under the `openresidency` npm organisation, owned by
HarmonizedX. Version 0.1.0 shipped on 2026-09-24, by hand, from a maintainer's login.

**Every version after that is published by `release.yml`**, through npm's trusted
publishing: the registry trusts the workflow's OIDC identity, so there is no publish token in
repository settings to leak, no second-factor prompt, and npm attaches provenance on its own
— the registry page shows the commit and workflow run that built the tarball. The `sdk` job
also refuses to publish when `sdk/package.json` does not match the tag.

### One-time setup, on npmjs.com

Package page → Settings → **Trusted Publisher** → GitHub Actions:

| Field | Value |
| --- | --- |
| Organization or user | `Harmonizedx` |
| Repository | `open-residency` |
| Workflow filename | `release.yml` |
| Environment name | leave empty |

Every field is case-sensitive and must be exact; the filename includes the extension. Then,
on the same settings page, set publishing access to **require two-factor authentication and
disallow tokens**. Trusted publishers are unaffected by that setting, and it closes the
token route for good.

### If the workflow cannot publish

A manual publish from a maintainer's login still works, and is the fallback:

```bash
cd sdk
npm run build
npm pack --dry-run    # expect four files: dist/index.js, dist/index.d.ts, package.json, README.md
npm publish --access public
```

`npm publish` triggers the account's second factor. Run it from a real terminal: npm opens
the browser to complete it, which works whether the account enrolled a passkey or an
authenticator app. Passing `--otp` is only needed when no browser is available. If tokens
have been disallowed as above, a manual publish is still allowed — that setting restricts
tokens, not logins.

## 3. Submit to the DPG Registry

Use `docs/DPG.md` as the answer set: the nine indicators are mapped to files in the repo,
and the "Registry submission pack" section at the end carries the project basics, the
attachments list, and a pre-submission checklist. Submit at digitalpublicgoods.net with
the public repo URL. The ownership indicator is satisfied by `NOTICE` and `GOVERNANCE.md`.

Indicators 7 and 8 are both closed — erasure and retention ship, as do Dependabot, CodeQL
and a CycloneDX SBOM. Two limits are worth stating rather than omitting: the retention
sweep covers residency records only, and nothing schedules it.

## 4. First deployment (optional, to have a live reference)

See `docs/DEPLOY.md`. A live instance at, for example, `https://id.katsina.gov.ng`
strengthens the DPG submission and gives partners something to try.

## Before you submit, confirm

- The release you cite exists, with every asset attached and the image digest in its notes.
- The SDK version on npm matches the tag: `npm view @openresidency/sdk version`.
- The production caveats in `README.md` are either addressed or clearly labeled, so the
  DPG do-no-harm review sees an honest, not oversold, project.