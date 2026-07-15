# Country configurations

Each YAML file here onboards one jurisdiction. No code change is required for a country
whose foundational identity provider is a normal REST API.

Four questions are answered declaratively:

1. Which foundational ID API do we verify against, and how? (`foundational`)
2. What must be true for someone to be issued residency? (`residency`)
3. What does the residency credential look like? (`credential`)
4. Which subnational units exist? (`subnationalUnits`)

Three optional blocks tune interoperability and sign-in:

5. Which wallets can obtain a credential, and on what terms? (`wallet`)
6. How are presentations requested? (`presentation`)
7. Which sector services can citizens sign into with their residency? (`oidc`)

Both default to the widest interoperable behaviour, so **omitting them is safe** — that is
what `ng.yaml`, `in.yaml`, and `ke.yaml` do. `demo.yaml` spells every knob out with the
reasoning attached. See [`docs/INTEROP.md`](../../docs/INTEROP.md) for what each one costs.

## Two profiles worth knowing

**Maximum compatibility (the default).** Offers `ldp_vc` and `jwt_vc_json`, accepts EdDSA,
ES256 and RS256, and speaks both OpenID4VCI Draft 13 and 1.0. This is what makes MOSIP's
Inji work without tuning — it is the hardest real wallet, not the only one.

**Strict.** For a deployment whose wallets have all moved to OpenID4VCI 1.0:

```yaml
wallet:
  formats: [ldp_vc]
  proofAlgs: [EdDSA]
  compatibility:
    draft13: false             # reject the legacy wire format outright
    cNonceInAccessToken: false # stop emitting the non-standard Inji claims
  offer:
    txCodeLength: 8
    maxTxCodeAttempts: 3
```

This is not merely cosmetic: with `draft13: false` a Draft 13 request is **rejected**, and
with `proofAlgs: [EdDSA]` an RS256 key proof is **refused**. Both are asserted in
`scripts/oid4vci-smoke.ts`, precisely so these knobs cannot quietly become decorative.

Narrowing is a security improvement — a smaller accepted request surface, and no
non-standard claims — so move here as soon as your wallets allow.

## Sign-in relying parties (`oidc`)

Sector services — Health, Tax, Permits, Subsidy — authenticate citizens through this
residency IdP ("Sign in with <State>"). They never see the national ID, only the
residency claims the citizen consents to release.

These used to be a hardcoded list in `src/sso/oidc.provider.ts`, which made a relying
party the **one** thing about a country that required a TypeScript edit. They are now
declared in config:

```yaml
oidc:
  relyingParties:
    - clientId: health
      name: Demoland Health Service
      sector: health
      redirectUris: [http://localhost:4001/callback]
      postLogoutRedirectUris: [http://localhost:4001]
```

Each RP is entitled to exactly one `sector` scope, added to the standard
`openid profile residency` set. Introducing a new sector needs no code change — the set
of registered scopes is derived from whatever the configured RPs actually use.

The client **secret is never in config**. It is read from `<CLIENT_ID>_CLIENT_SECRET` in
the environment (e.g. `HEALTH_CLIENT_SECRET`), falling back to a `<id>-dev-secret`
placeholder only when unset, so local development works with no secrets configured. Set a
real secret per RP in production.

Omit the `oidc` block entirely and no relying parties are registered — which is what a
deployment that does not use SSO wants.
