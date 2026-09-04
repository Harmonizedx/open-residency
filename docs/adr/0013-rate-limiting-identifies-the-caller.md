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

`ThrottlerGuard` keys that budget on `req.ip` (`@nestjs/throttler@6.5.0`). Express derives
`req.ip` from the socket peer unless `trust proxy` is set, in which case it reads the client
address out of `X-Forwarded-For` instead — and `trust proxy` **is set nowhere** in this
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

**D. Key on the authenticated principal.** More meaningful than an address, and the obvious
answer for an enrolment desk. **It cannot be done from a global guard.** Rate limiting runs
before authentication — that is the point of a rate limiter — so at that moment a presented
credential is an unverified string. Keying on one lets an anonymous caller rotate a header and
receive a fresh, empty budget per request: not a weaker limit, no limit at all, and the same
failure as option A wearing another hat. Doing it safely means throttling *after*
authentication, which is a second mechanism rather than a variation of this one.

## Decision

**Rate limiting keys on the client address, and nothing the caller controls reaches the key.**

1. **The client address, derived from a declared hop count.** `TRUSTED_PROXY_HOPS` states how
   many proxies sit in front, and only that many entries of `X-Forwarded-For` are believed,
   counted from the right where the entries were appended by infrastructure we control. It
   defaults to `0` — direct exposure, today's behaviour for anyone not behind a proxy — and is
   never guessed at. Declaring more hops than a request actually traversed falls back to the
   socket peer rather than reading the caller-supplied head of the chain.

2. **A mismatch is reported, not absorbed.** When a request arrives carrying
   `X-Forwarded-For` while the hop count is `0`, the application says so, once, plainly: it is
   behind a proxy and the limit is counting the proxy rather than the caller.

**Rejected:** A, as strictly worse than the defect. D from a global guard, for the same reason
— it is option A relocated to a different header. C as the *only* control, though an ingress
limit remains sound defence in depth.

**Deferred: per-operator budgets.** A ward office behind one NAT is a single address, so
address-keyed limiting still shares one budget across a busy office. Fixing that needs a
throttle applied *after* `OperatorGuard`, keyed on the resolved operator rather than a
presented string. That is a separate mechanism and a separate change; recording it here so the
gap is known rather than assumed closed.

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

- Every caller behind one address still shares a budget, including a busy enrolment office.
  This decision makes the limit count the right address; it does not make it count people. See
  the deferred item above.
- A distributed source can still consume an address's budget. An ingress-level limit remains
  worth having in front.
- `TRUSTED_PROXY_HOPS` becomes part of what a deployment declares, alongside its database
  URL and pepper. `DEPLOY.md` and the Helm chart carry it.
- `docs/API.md` must stop describing the limit as per-caller without qualification, because
  for anonymous traffic behind an unconfigured proxy it is not.

## How this is verified

`scripts/ratelimit-smoke.ts`, chained into `npm test`: a declared hop count reads the client
address from `X-Forwarded-For` while an undeclared one does not; a spoofed header cannot change
the key when no proxy is declared; a caller prepending entries cannot steer the key past the
declared hops; declaring more hops than were traversed falls back to the socket peer rather
than the caller-supplied head; the mismatch is reported; and — the regression test for the
first implementation of this record — two requests from one address share a bucket regardless
of what headers they carry.
