# Publishing OpenResidency

Everything is built and packaged. Publishing is now a sequence of pushes, done with
HarmonizedX's accounts. This is the runbook.

## 1. Create the public repository

Create `openresidency` under the HarmonizedX GitHub org (confirm the exact org handle;
the metadata currently assumes `harmonizedx`). Then:

```bash
git init
git add .
git commit -m "OpenResidency: initial public release"
git branch -M main
git remote add origin https://github.com/Harmonizedx/open-residency.git
git push -u origin main
```

CI (`.github/workflows/ci.yml`) runs on pull request and on push to `main`: typecheck, W3C
conformance, and the core, OpenID4VCI, OpenID4VP, SSO, and foundational-source suites, plus
a Docker image build. Confirm it is green. Note CI does **not** build or publish the SDK —
that is the manual step below.

If the org handle is not `harmonizedx`, update it in: root `package.json`, `sdk/package.json`,
the image references in `deploy/`, and the URLs in `docs/`.

## 2. Publish the SDK to npm

Create the `@openresidency` org/scope on npm (owned by HarmonizedX). Publishing is manual —
there is no release workflow in this repository yet, so tagging alone does not ship
anything:

```bash
cd sdk && npm run build && npm publish --access public
```

## 3. Submit to the DPG Registry

Use `docs/DPG.md` as the answer set: the nine indicators are mapped to files in the repo,
and the "Registry submission pack" section at the end carries the project basics, the
attachments list, and a pre-submission checklist. Submit at digitalpublicgoods.net with
the public repo URL. The ownership indicator is satisfied by `NOTICE` and `GOVERNANCE.md`.

Two indicators are recorded there as incomplete (privacy: no PII erasure or retention;
best practices: no dependency scanning or SBOM). Resolve or disclose them before
submitting — do not answer around them.

## 4. First deployment (optional, to have a live reference)

See `docs/DEPLOY.md`. A live instance at, for example, `https://id.katsina.gov.ng`
strengthens the DPG submission and gives partners something to try.

## Before you publish, confirm

- Org handle is correct across metadata (default assumed: `harmonizedx`).
- `NPM_TOKEN` secret is set for the SDK publish.
- The production caveats in `README.md` are either addressed or clearly labeled, so the
  DPG do-no-harm review sees an honest, not oversold, project.
