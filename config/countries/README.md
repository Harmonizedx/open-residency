# Country configurations

Each YAML file here onboards one jurisdiction. No code change is required for a country
whose foundational identity provider is a normal REST API.

Four questions are answered declaratively:

1. Which foundational ID API do we verify against, and how? (`foundational`)
2. What must be true for someone to be issued residency? (`residency`)
3. What does the residency credential look like? (`credential`)
4. Which subnational units exist? (`subnationalUnits`)

Two optional blocks tune wallet interoperability:

5. Which wallets can obtain a credential, and on what terms? (`wallet`)
6. How are presentations requested? (`presentation`)

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
