# 13. Rate limiting identifies the caller, and says so when it cannot

- Status: **Proposed** — implementation lands in the same change, but the choice below is
  the sort a maintainer should agree to rather than inherit from a commit.
- Date: 2026-08-23
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md)

## Context

The application registers one global limit:

```ts
ThrottlerModule.forRoot([{ name: 'default', ttl: 60_000, limit: RATE_LIMIT_PER_MINUTE ?? 120 }])
{ provide: APP_GUARD, useClass: ThrottlerGuard }
```

`ThrottlerGuard` keys that budget on `req.ips[0] ?? req.ip`. Express only populates `req.ips`
from `X-Forwarded-For` when `trust proxy` is set, and **it is set nowhere** in this
repository. The documented deployment fronts the application with an nginx ingress
(`deploy/k8s/ingress.yaml`), so every request presents the ingress pod's address.

The limit is therefore **one bucket for the entire deployment**, not one per caller. Any
single client — or one looping script — can spend the whole budget and 429 every other
caller, including a registrar mid-enrolment. No credentials are required to do it.

Two things make it worse than a mis-sized limit.

`ThrottlerGuard` is a global `APP_GUARD`, so it runs **before** controller guards. An
unauthenticated caller consumes budget on routes they are not permitted to reach; the guard
on the route does not protect the route's budget.

And it fails **silently and plausibly**. Nothing logs, nothing 500s, the limit appears to
work. Every deployment behind a proxy has been running this way, and the only symptom is
occasional unexplained 429s during busy periods — which reads as "the limit is too low", so
the natural response is to raise it, which widens the hole.

Surfaced while reviewing #139, which had added a *tighter* 20/min bucket on
`/identity/challenge` and would have made the lockout six times cheaper.

## Options considered

**A. `app.set('trust proxy', true)`.** One line, and **worse than the bug**.
`X-Forwarded-For` is client-supplied: with blanket trust, any caller sets it to a fresh
value per request and evades the limit entirely. It converts "one bucket for everyone" into
"a bucket per attacker, on request".

**B. Declared hop count.** `app.set('trust proxy', N)` where the deployment states how many
proxies sit in front. Correct when configured. Silently wrong when not, which is the failure
mode we are already in.

**C. Push rate limiting to the ingress; drop it from the app.** The ingress is the only
component that reliably knows the real client. But it moves a security control out of the
artifact this project ships: a deployment that misconfigures nginx then has no limit at all,
and nothing in the repository would tell them. It also cannot express "per operator", only
"per address".

**D. Key on the authenticated principal.** Unspoofable and more meaningful than an address —
but it answers nothing for the wallet-facing and `.well-known` routes, which are
unauthenticated by specification and are exactly where anonymous volume arrives.

## Decision

**Rate limiting keys on the strongest identifier the request actually carries, and the
deployment declares its own topology.**

1. **An authenticated principal, where there is one.** The operator guard already resolves
   `ork_…` keys and bearer tokens; the limit keys on that operator. Unspoofable, and a
   registrar's desk gets its own budget rather than sharing one with the building.

2. **Otherwise the client address, derived from a declared hop count.** `TRUSTED_PROXY_HOPS`
   states how many proxies sit in front. It defaults to `0` — direct exposure, today's
   behaviour for anyone not behind one — and is not guessed at.

3. **A mismatch is reported, not absorbed.** When a request arrives carrying
   `X-Forwarded-For` while the hop count is `0`, the application says so, once, plainly:
   it is behind a proxy and the limit is counting the proxy rather than the caller.

**Rejected:** A, as strictly worse than the defect. C as the *only* control, though an
ingress limit remains sound defence in depth.

## Why

**The silence is the defect.** A limit that is wrong is a bug; a limit that is wrong and
looks right is why this survived. Part 3 is the part that stops it recurring, and it is the
part that would have caught it originally.

**Defaulting to `0` breaks nobody.** A deployment running directly is already correct. A
deployment behind a proxy is already broken, and now finds out. Requiring every deployment
to declare the value would match this repository's line that config accepted and then
ignored is worse than config refused — but it imposes a new mandatory variable on people
whose behaviour does not change, so the warning carries that weight instead.

**Keying on the operator is the part that actually helps the enrolment desk.** Address-based
limits are a poor fit for the deployments this platform targets: a ward office behind one
NAT presents as a single address, so per-address limiting punishes exactly the busy office
it is meant to protect. Per-operator does not.

## Consequences

- Authenticated callers are limited individually; the budget stops being collective for
  them.
- Anonymous routes remain address-keyed, and remain the place where a distributed source can
  still consume the budget. This decision narrows that surface; it does not remove it, and
  an ingress-level limit is still worth having in front.
- `TRUSTED_PROXY_HOPS` becomes part of what a deployment declares, alongside its database
  URL and pepper. `DEPLOY.md` and the Helm chart carry it.
- `docs/API.md` must stop describing the limit as per-caller without qualification, because
  for anonymous traffic behind an unconfigured proxy it is not.

## How this is verified

`scripts/*.ts` assertions that: an authenticated request keys on the operator rather than the
address; two operators from one address do not share a budget; a declared hop count reads the
client address from `X-Forwarded-For` while an undeclared one does not; and a spoofed
`X-Forwarded-For` with no declared hops cannot change the key. Plus one asserting that the
mismatch between a forwarded header and a zero hop count is reported.
