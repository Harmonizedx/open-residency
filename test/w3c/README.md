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

It also starts `test/w3c/auth-proxy.cjs` on `127.0.0.1:3100` for the duration of the run,
and stops it afterwards. The suite honours the `Authorization` header from
`localConfig.cjs` only when the target is `https:`; over plain `http:` it builds the request
by hand and drops it, so every call would otherwise reach the admin-guarded VC-API
unauthenticated and the whole suite would fail with `401` — dozens of results that look
like conformance failures and are not. The shim adds the credential rather than removing
the guard. Override its port with `W3C_PROXY_PORT`.

### Honest status

**The suite passes 59 of 59 against a local instance. It is still not run in CI, and this
repository does not claim a green CI run.** It needs a live server and a database, so it
stays opt-in; the number above is what a reviewer gets by following the steps above, not
something a build enforces. The hermetic layer 1 suite is what protects these rules on
every commit — the checks it grew alongside these fixes are listed under
"Sub-objects MUST specify a type", "relatedResource integrity", "Verifiable presentations"
and "Language value objects" in `npm run test:conformance`.

If you run it and see anything other than 59/59, please open an issue with the output.
Failures against the W3C suite are exactly the issues we most want filed.

Two predictions this document previously made, and how they actually turned out:

- We expected the **pinned JSON-LD loader** to be the main source of failures, since the
  suite exercises credential shapes far beyond residency. It was not: every context the
  suite uses is already pinned in `contexts/`, and the loader refusing network fetches
  never came up. The prediction was reasonable and simply wrong. If you extend the suite
  and hit `refusing to fetch remote JSON-LD context`, that is the loader working as
  designed — pin the context under `contexts/` and register it in `CONTEXT_FILES`.
- `POST /presentations/verify` **now verifies the presentation's proof**, against the key
  its own `verificationMethod` names, resolved offline from `did:key`. It still cannot
  check holder binding, nonce, or audience, because a bare VC-API presentation carries no
  challenge — it says so in its own `warnings`. The real presentation path is OpenID4VP
  (`/openid4vp/response`), which checks all three.

`relatedResource` digests (VCDM 2.0 §5.3) are verified only for resources this deployment
already pins. Fetching an arbitrary URL to digest it is the thing the loader exists to
refuse, so an unpinned resource is left unverified rather than fetched — or rejected, which
would make a valid resource unusable.

## Why the VC-API endpoints are guarded

They will sign broadly what they are handed. An unauthenticated generic signing oracle
operating under a government issuer's DID would let anybody mint a credential that appears
to come from the state — a considerably worse outcome than failing a test suite. So they
sit behind `ADMIN_API_KEY`, and they are **not** how residency credentials are issued in
production. That is OpenID4VCI, which binds each credential to a key held by the citizen.
