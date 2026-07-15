# Contributing to OpenResidency

Thanks for helping build open residency infrastructure. This project is stewarded by
HarmonizedX Limited and released under Apache-2.0.

## Ground rules

- By submitting a contribution, you agree it is licensed under Apache-2.0
  (inbound-equals-outbound). No separate CLA is required.
- Be respectful. Assume good faith.
- Never commit secrets, real national ID numbers, or personal data, including in tests
  or fixtures. Use the MOCK provider and synthetic values.

## Contribution workflow

Every contribution — from a HarmonizedX engineer or a first-time external contributor —
follows the same lifecycle and is held to the same review standard. The
[GitHub issue tracker](https://github.com/harmonizedx/openresidency/issues) is the single
source of truth for planned work.

```text
Issue → Discussion & assignment → Development → Pull request → Review → CI → Approval → Merge
```

### 1. Start with an issue

Before writing code, search the existing issues. If the work has not been proposed, open a
new issue describing the change. For anything substantial — a new standard, a breaking API
change, or a change to the privacy or security model — discuss it in the issue and wait for
maintainer agreement before starting, so effort is not spent on a direction the project
will not take. (This mirrors the "substantial changes need a written proposal" rule in
[`GOVERNANCE.md`](GOVERNANCE.md).)

### 2. Get the code

The only difference between internal and external contributors is **where you develop**.

- **HarmonizedX organization members** with write access branch directly from the latest
  `main` in this repository.
- **External contributors** fork the repository, clone the fork, and branch there. You do
  not need write access to contribute; you open your pull request from your fork.

### 3. Create a feature branch

Branch from an up-to-date `main`, and name the branch for its purpose:

```
feat/esignet-adapter        bugfix/nonce-replay
feat/vp-sso-login           hotfix/security-patch
docs/update-contributing    test/oid4vp-coverage
```

Commit messages follow the same `type(scope): summary` convention as the git history
(`feat`, `fix`, `test`, `docs`, `chore`, …).

### 4. Develop, then open a pull request

Implement the change, keep it focused on one concern, and follow the setup, testing, and
"what not to break" guidance below. Then open a pull request that references its issue.
`main` is a **protected branch**: direct pushes are rejected, and every change lands through
a reviewed, CI-passing pull request. See [Pull requests](#pull-requests) for the checklist.

## Commits must be signed

**This repository requires verified commit signatures.** An unsigned push is rejected, so
set this up before your first commit — otherwise you will write the code and then discover
you cannot push it.

SSH signing is the simplest route, using a key you probably already have:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then register that **same key** on GitHub as a **Signing Key** — at
<https://github.com/settings/ssh/new>, set *Key type* to `Signing Key`. This is a separate
entry from the Authentication key you push with; adding it once as "Authentication" is the
usual reason commits still show as Unverified.

To have `git log` verify signatures locally as well:

```bash
mkdir -p ~/.config/git
echo "your@email $(cat ~/.ssh/id_ed25519.pub | awk '{print $1" "$2}')" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Check it worked — `%G?` should print `G`:

```bash
git log --format='%h %G? %s' -3
```

If your key has a passphrase, load it first: `ssh-add ~/.ssh/id_ed25519`.

## Development setup

```bash
npm install
npm run prisma:generate   # generates the Prisma client; no database needed
npm test                  # every check below, ~30s, no database, no network
```

To run the server you also need Postgres:

```bash
cp .env.example .env
docker compose up -d db
npm run prisma:migrate
npm run start:dev
```

## Tests

`npm test` runs everything CI runs. Each suite is a plain script — no test framework — and
prints one line per assertion, so a failure tells you what broke rather than where.

| Command | What it covers |
|---|---|
| `npm run typecheck` | Full TypeScript check across the Nest layer and core |
| `npm run smoke` | The framework-agnostic core: config, adapters, credentials, consent, audit, offline |
| `npm run smoke:oid4vci` | Drives issuance **as a wallet**, in both OpenID4VCI dialects, plus the attacks it must reject |
| `npm run smoke:oid4vp` | Drives a presentation from both sides, plus the attacks it must reject |
| `npm run test:conformance` | W3C VC Data Model 2.0, Bitstring Status List, and Data Integrity conformance |

CI runs all of these on every pull request, and builds the Docker image.

### The official W3C test suite

`npm run test:w3c` runs [`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite)
against a **running** instance, over the VC-API. It needs a server and a database, so it is
not part of CI. See [`test/w3c/README.md`](test/w3c/README.md), which is explicit about what
we have and have not run. **We do not claim to pass it.** If you run it, please open an
issue with the output — those are the issues we most want.

## What to work on

- New foundational adapters (or config-only country files under `config/countries`).
- Wallet interoperability: see [`docs/INTEROP.md`](docs/INTEROP.md). If a wallet cannot
  complete issuance, add a case to `scripts/oid4vci-smoke.ts` that reproduces its
  behaviour, watch it fail, then fix the issuer.
- Hardening the items listed as caveats in `README.md` (real SSO factor, KMS signing).
- Additional language SDKs generated from `docs/openapi.yaml`.
- Documentation and deployment recipes.

## What not to break

Some checks look like defensive clutter and are in fact the whole point. Please do not
relax any of these to make a wallet work — narrow the config instead
(see [`config/countries/README.md`](config/countries/README.md)):

- **The key proof is mandatory at issuance.** A credential with no holder binding is a
  bearer token: whoever holds the bytes can use it.
- **Nonces are single-use**, consumed with a conditional DELETE. A read-then-delete races,
  and the race *is* the replay attack.
- **Presentations check holder binding, nonce, and audience.** Drop any one and the
  credential collapses back into a bearer token. A stolen credential presented under
  someone else's key must fail.
- **The presentation path fails closed on revocation.** Offline credential verification is
  deliberately permissive; online presentation is not.
- **JSON-LD contexts are pinned and never fetched**, and canonicalization runs in safe
  mode. Without safe mode, a term missing from the `@context` is *silently dropped from
  what the signature covers* — the credential still verifies while attesting less than it
  appears to.

Each of these has a test asserting it is rejected **for the right reason**, not merely that
something failed. If you change one, the test should change with it and the PR should say
why.

## Pull requests

- Reference the issue the PR resolves (`Closes #123`).
- Keep changes focused. One concern per PR.
- Sign your commits (see above) and write a descriptive commit body — say *why*, not what.
- Add or update a check in the relevant `scripts/*.ts` suite when you change core logic.
- Run `npm test` before pushing. CI runs the same thing.
- Update `docs/openapi.yaml` when you change the HTTP surface, and the SDK to match.
- Update `docs/INTEROP.md` when you change anything a wallet sees.
- Describe privacy or security implications explicitly in the PR.

### What review looks at

A maintainer reviews every pull request against `main` before it can merge. Expect
feedback on any of: correctness, security and privacy posture, code quality and
maintainability, test coverage (a core-logic change without a matching `scripts/*.ts`
assertion will be sent back), and documentation completeness. Constructive discussion
before approval is normal — it is how the change gets better, not a rejection.

### CI must pass

Every pull request runs the automated pipeline in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml): the Prisma client is generated, the
project is typechecked, the core / OpenID4VCI / OpenID4VP / W3C-conformance suites all run,
and the Docker image is built to prove `contexts/` ships in the runtime image. A pull
request with failing checks cannot be merged. These runs are hermetic — no database, no
network — so a green run locally (`npm test`) is a green run in CI.

## Reporting bugs

Open an issue with steps to reproduce. For security issues, do not open a public
issue; follow `SECURITY.md`.
