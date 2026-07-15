# Contributing to OpenResidency

Thanks for helping build open residency infrastructure. This project is stewarded by
HarmonizedX Limited and released under Apache-2.0.

## Ground rules

- By submitting a contribution, you agree it is licensed under Apache-2.0
  (inbound-equals-outbound). No separate CLA is required.
- Be respectful. Assume good faith.
- Never commit secrets, real national ID numbers, or personal data, including in tests
  or fixtures. Use the MOCK provider and synthetic values.

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

- Keep changes focused. One concern per PR.
- Sign your commits (see above) and write a descriptive commit body — say *why*, not what.
- Add or update a check in the relevant `scripts/*.ts` suite when you change core logic.
- Run `npm test` before pushing. CI runs the same thing.
- Update `docs/openapi.yaml` when you change the HTTP surface, and the SDK to match.
- Update `docs/INTEROP.md` when you change anything a wallet sees.
- Describe privacy or security implications explicitly in the PR.

## Reporting bugs

Open an issue with steps to reproduce. For security issues, do not open a public
issue; follow `SECURITY.md`.
