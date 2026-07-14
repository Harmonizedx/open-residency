# Running the official W3C test suites

There are two layers of conformance testing in this repository, and it matters which is
which. We would rather be precise about that than claim more than we have earned.

## Layer 1 — `npm run test:conformance` (runs in CI, on every PR)

Asserts the normative MUSTs of [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
[Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/), and
[VC Data Integrity](https://www.w3.org/TR/vc-di-eddsa/) against credentials we actually
issue, in both formats — and checks that credentials violating those MUSTs are *rejected*,
not just that valid ones are accepted.

It is fast, hermetic, needs no network and no database, and it gates every commit. It is
also the check that caught a real bug: our `encodedList` was bare base64url where the spec
requires *multibase* base64url, so a strict verifier would have read the leading `H` of the
GZIP magic bytes as a base identifier and decoded garbage.

**It is a suite we wrote ourselves.** It is not the W3C's, and passing it is not the same
as passing theirs. Which brings us to:

## Layer 2 — the official W3C suites (opt-in, not in CI)

[`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite)
is the actual authority. It drives an implementation over the
[VC-API](https://w3c-ccg.github.io/vc-api/) — which this deployment now exposes precisely
so that the suite *can* be pointed at it:

```
POST /credentials/issue
POST /credentials/verify
POST /presentations/verify
```

### Running it

It needs a live server, and therefore a database. It is not hermetic, so it does not gate
commits.

```bash
# 1. Bring up the stack
cp .env.example .env
docker compose up -d db
npm run prisma:migrate
ADMIN_API_KEY=dev-admin-key npm run start:dev

# 2. In another shell, run the suite against it
ADMIN_API_KEY=dev-admin-key npm run test:w3c
```

`npm run test:w3c` clones the suite into `test/w3c/.suite/` (gitignored), installs it, and
runs it with `test/w3c/localConfig.cjs`, which points at `http://localhost:3000`. Override
the target with `W3C_SUITE_BASE_URL`.

### Honest status

**We have not run the official suite green in CI, and this repository does not claim to.**
The harness, the VC-API endpoints, and the config are here so that a reviewer, a DPG
assessor, or a contributor can run it themselves and see the result first-hand — which is
the point. If you run it, please open an issue with the output, whatever it says. Failures
against the W3C suite are exactly the issues we most want filed.

Two things we already expect to need work when it is run:

- The suite exercises credential shapes far beyond residency (arbitrary `@context`s,
  example vocabularies). Our JSON-LD document loader is deliberately **pinned and refuses
  network fetches**, for the determinism, availability, and integrity reasons set out in
  `docs/INTEROP.md`. Any context the suite uses that we have not pinned in `contexts/` will
  fail to canonicalize. That is the loader working as designed, not a bug — but it means
  running the suite will likely surface contexts to add.
- `POST /presentations/verify` cannot check holder binding, nonce, or audience, because a
  bare VC-API presentation carries no challenge. It says so in its own `warnings`. The real
  presentation path is OpenID4VP (`/openid4vp/response`), which checks all three.

## Why the VC-API endpoints are guarded

They will sign broadly what they are handed. An unauthenticated generic signing oracle
operating under a government issuer's DID would let anybody mint a credential that appears
to come from the state — a considerably worse outcome than failing a test suite. So they
sit behind `ADMIN_API_KEY`, and they are **not** how residency credentials are issued in
production. That is OpenID4VCI, which binds each credential to a key held by the citizen.
