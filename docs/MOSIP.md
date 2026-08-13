# Working with a MOSIP deployment

OpenResidency is not built on MOSIP and does not require it. But a subnational government
adopting this is very often working inside a country that already runs MOSIP nationally, and
in that case the residency system should use the national identity that already exists rather
than ask residents to prove themselves twice.

"MOSIP support" is not one thing. It is four distinct integration surfaces, and a deployment
may need any subset of them. This document covers what each one does, what it establishes,
what it deliberately does not, what you must obtain before it will run, and how far it has
actually been verified.

**Read the last section before quoting any of this.** Three of the four surfaces are verified
against reference implementations and documented behaviour, not against a live MOSIP stack.
That distinction is load-bearing and this project does not blur it.

---

## At a glance

| Surface | Direction | Status | Verified by |
| --- | --- | --- | --- |
| **Inji / OpenWallet issuance** | We issue → their wallet holds | Complete | `npm run smoke:inji` |
| **Inbound credential verification** | Their issuer signs → we verify | Complete | `npm run smoke:ld-suites` |
| **eSignet sign-in** | Their IdP authenticates → we accept | Complete | `npm run smoke:upstream-oidc` |
| **IDA foundational auth** | We authenticate against their registry | Auth complete; eKYC not implemented | `npm run smoke:mosip-ida` |

All four are gated in CI on every pull request.

---

## 1. Issuing credentials an Inji wallet can hold

This was the first surface built and is documented in full in
[`docs/INTEROP.md`](INTEROP.md#compromises-made-for-real-wallets). In short: residency
credentials are issued over OpenID4VCI as `ldp_vc` with a `DataIntegrityProof`
(`eddsa-rdfc-2022`), which is what Inji accepts — it rejects `jwt_vc_json` outright.

Three accommodations exist specifically because real wallets need them, and each is
configurable rather than hardcoded:

- `ldp_vc` is offered alongside `jwt_vc_json` (the latter is the offline/QR path).
- `RS256` is an accepted holder-proof algorithm, because Inji hardcodes it.
- `c_nonce` is echoed inside the access token (`compatibility.cNonceInAccessToken`), which
  is in **no** version of the spec and exists solely because Inji reads it from there.

There is no wallet sniffing anywhere in the codebase. Inji is simply the strictest wallet to
satisfy, so satisfying it satisfies the others.

## 2. Verifying credentials a MOSIP deployment issued

The direction that was missing until now. Every verification path here was Ed25519 and
`eddsa-rdfc-2022` only — down to the trust-list schema refusing any key that was not `OKP` —
so a credential from an Inji Certify issuer could not be verified at all. Not rejected on its
merits: unreadable.

`src/core/credentials/ld-suites.ts` now verifies three further suites:

| Suite | Signature carried in | Algorithms accepted |
| --- | --- | --- |
| `Ed25519Signature2020` | `proofValue`, multibase base58btc | Ed25519 |
| `Ed25519Signature2018` | `jws`, detached (RFC 7797) | `EdDSA` |
| `RsaSignature2018` | `jws`, detached (RFC 7797) | `PS256` **and** `RS256` |

Three constraints are deliberate and worth understanding before you enable any of them.

**Verify-only.** There is no signing path for these suites. Nothing in that file can produce
a proof. Accepting a legacy suite is an obligation to issuers we do not control; emitting one
would be a choice, and the choice is no. We issue `eddsa-rdfc-2022` and will continue to.

**Opt-in per peer.** A suite is accepted from the peer that declares it and from nobody else.
Federating with one MOSIP-era issuer must not widen what every other peer in your trust list
may send you.

**Fail closed, with distinct reasons.** An unpinned context, `alg: none`, an RSA algorithm on
an Ed25519 suite, a proof made for `authentication` offered as an `assertionMethod` — each
returns its own reason rather than a generic failure, because those have different fixes.

### Two interoperability details that cost real debugging time

`RsaSignature2018` is accepted with **both** `PS256` and `RS256`. The suite's specification
says RS256; the reference implementation most issuers were built on emits PS256. Credentials
in the field carry whatever their issuer's library produced, and the JWS header states which,
so there is no ambiguity to resolve — only a choice about whether to reject genuine
credentials on a technicality nobody agrees about.

Implementations also disagree about which context the **proof options** are canonicalized
under: `jsonld-signatures` 11.x uses the enclosing document's `@context`, its 5.x line
hardcodes `https://w3id.org/security/v2`. The same credential therefore has two legitimate
canonical forms depending on who signed it, so both are tried. This is not a weakening: each
is fully specified, the signature must still verify against a key already in your trust list,
and a forger able to sign over one form could sign over the other.

### Configuring a peer

```yaml
federation:
  trustedIssuers:
    - did: did:web:id.partner.example.gov
      name: A MOSIP-era partner issuer
      publicJwks:
        - { kty: RSA, n: "<base64url>", e: AQAB, kid: partner-rsa-1 }
      acceptedProofSuites: [RsaSignature2018]
      contexts:
        - url: https://partner.example.gov/contexts/residency/v1
          document:
            "@context":
              "@version": 1.1
              "@protected": true
              PartnerResidencyCredential: https://partner.example.gov/vocab#PartnerResidencyCredential
```

The `contexts` block is not optional bookkeeping. The peer defines its credential terms in a
context document it hosts; canonicalizing its credentials requires that document, and the
loader refuses to fetch anything at verification time — for determinism, for offline
verifiers, and because whoever serves a context influences what the signature is understood
to cover. So you pin it next to the peer's keys and review it with them. A peer-supplied
context cannot shadow a built-in one, and two peers cannot claim the same URL with different
content.

## 3. Signing residents in with eSignet

`upstreamOidc` makes this deployment a **relying party** at an external OpenID Provider.
Where the rest of the system is the provider, this is the reverse.

The reason to do it is not convenience. A registry lookup establishes that an identity record
exists — anyone holding the number passes it, and the applicant is bound to that identity by
nothing. An eSignet sign-in establishes that the source itself just confirmed the owner was
present, which is `authoritative_authentication`: the strongest binding in
`src/core/proofing/binding.ts`. It is the difference between a residency claim a resident can
make themselves and one an operator must key in for them.

There is no eSignet-specific code. eSignet is simply the strictest provider likely to be on
the other end, so supporting it means supporting the strict end of the standard:

| eSignet requires | What that means here |
| --- | --- |
| `private_key_jwt` as the **only** client auth method | A signed RS256 assertion per token request, audienced at the **token endpoint** (RFC 7523 §3), with a unique `jti` |
| A userinfo response that is signed **then encrypted** | Decrypt to your key, then verify the provider's signature on what is inside. Decrypting alone proves someone encrypted to you, not that the provider asserted anything |
| A pairwise `sub` | Already scoped to you; it is HMAC'd under the deployment pepper anyway, so the residency store never holds the provider's identifier |
| `acr` naming the method used | Mapped in config to what you credit it with. An unmapped `acr` **fails the sign-in** |

Two choices go beyond what eSignet demands. PKCE is used unconditionally — "not redeemable
without a verifier we never transmitted" is stronger than "not redeemable by anyone who
cannot sign as us". And the provider's signing keys are **pinned** in config rather than
fetched from `jwks_uri`, because whoever answers for that URL at sign-in time would otherwise
decide which `id_token`s you believe.

### The acr mapping is a policy decision, not a default

```yaml
upstreamOidc:
  issuer: https://esignet.example.gov
  authorizationEndpoint: https://esignet.example.gov/authorize
  tokenEndpoint: https://esignet.example.gov/v1/esignet/oauth/v2/token
  userinfoEndpoint: https://esignet.example.gov/v1/esignet/oidc/userinfo
  jwks:
    - { kty: RSA, n: "<base64url>", e: AQAB, kid: op-key-1, alg: RS256, use: sig }
  clientId: openresidency-yourstate
  redirectUri: https://id.yourstate.gov/sso/upstream/callback
  acrValues: ["mosip:idp:acr:biometrics", "mosip:idp:acr:generated-code"]
  acrMapping:
    - { acr: "mosip:idp:acr:biometrics", assurance: high }
    - { acr: "mosip:idp:acr:generated-code", assurance: verified }
  clientAssertionKeyEnv: UPSTREAM_CLIENT_ASSERTION_KEY
  userinfoDecryptionKeyEnv: UPSTREAM_USERINFO_DECRYPTION_KEY
```

eSignet advertises `mosip:idp:acr:password`, `:generated-code`, `:linked-wallet` and
`:biometrics`. There is deliberately **no default mapping and no inferred ordering**. Only
you know what your deployment's "password" actually establishes about a person, and the value
you choose reaches every relying party as `assurance_level`. An `acr` your provider returns
that you have not listed fails the sign-in rather than being credited with something — it is
a method you have said nothing about, and grading it at runtime would be inventing policy.

## 4. MOSIP ID Authentication as the foundational provider

Most national ID APIs are one REST call and need no code: describe the request and the
response mapping in YAML and you are done. IDA is the exception — its request body is an
encrypted envelope — so it has a real adapter (`provider: MOSIP_IDA`). Nothing about the
envelope is configurable; it is fixed by MOSIP.

### What a success establishes

IDA **authenticates**: by an OTP delivered to the device registered on the authoritative
record, or by a demographic match performed by the authority. So a success attests
`authoritative_authentication`, not the `none` that a bare lookup earns.

What it does **not** do is retrieve attributes. `/auth` answers yes or no. The attributes on a
successful result here are the ones the applicant submitted and MOSIP **confirmed** — which
is a stronger statement than a lookup returning them, and the only one this endpoint
supports. Attribute retrieval is the separate eKYC endpoint; its response decryption needs a
partner encryption key and a live deployment to test against, so it is **not implemented**
rather than implemented blind. If you need demographic retrieval, that is the next piece of
work, and it should be built against a sandbox rather than from documentation.

### The envelope

Six things must all be right, and three are the opposite of what a careful reader would
assume. Each was taken from MOSIP's own client code — `CryptoCore` in `mosip/keymanager` and
the eSignet integration helper in `mosip/id-authentication` — rather than inferred from prose:

1. A fresh AES-256 session key encrypts the request block, GCM. **The IV is appended after
   the ciphertext and tag, not prepended** — MOSIP's decrypt reads it from the final bytes —
   **and it is 16 bytes**, sized from the AES block size rather than GCM's usual 12.
2. The session key is encrypted to MOSIP's partner certificate: RSA-OAEP, SHA-256, MGF1-SHA-256.
3. `requestHMAC` is a SHA-256 digest of the **plaintext** block in **uppercase** hex,
   encrypted under that same session key. It is not a MAC over the ciphertext, despite the name.
4. `thumbprint` is SHA-256 over the certificate's DER, so MOSIP knows which key to use after
   a rotation.
5. The body is signed as a detached JWS in a `signature` header, `x5c` carrying the partner
   certificate, over the exact bytes transmitted rather than a re-serialization of them.
6. **Every base64 field is URL-safe and unpadded.**

Getting any one of these wrong produces a request the server rejects with an error that does
not say which part was wrong. That is why the test server in `npm run smoke:mosip-ida` opens
the envelope rather than merely accepting it.

### What you must obtain first

None of this can be defaulted, and the adapter **refuses to start** without it. All of it
comes from partner onboarding, not from this repository:

- registration as an auth partner under a MISP, and the **MISP licence key**
- your **partner id**, and the policy-linked **partner API key**
- your **signing and encryption certificates**, uploaded through the partner portal
- **MOSIP's own partner certificate**, which the session key is encrypted to

Secrets are named as environment variables in config, never inlined. The two certificates are
public material and belong in the config file; the private keys they correspond to do not.

See [`config/countries/demo.yaml`](../config/countries/demo.yaml) for the full annotated
block.

---

## How far this is actually verified

This is the section to read before repeating any claim above.

**What the test suites establish.** They are not self-round-trips. For the proof suites, the
credentials driven through verification were produced by the **reference implementations** —
`@digitalbazaar/ed25519-signature-2020` and `-2018` over `jsonld-signatures` 11.6.0, and
`jsonld-signatures` 5.2.0 for `RsaSignature2018`, the last release that bundled it. If our
canonicalization, proof-options handling or reading of RFC 7797 differs from theirs by one
byte, the suite fails. For IDA, the test server decrypts the session key, decrypts the block,
recomputes the digest, checks the thumbprint and verifies the detached JWS — so a client that
got the IV placement or the digest case wrong fails there exactly as it would in production.
For eSignet, the provider is built to its published configuration and each failure mode is
asserted individually: replayed callback, nonce from another session, unmapped `acr`,
`id_token` signed by an unpinned key, a provider that switches subject between `id_token` and
userinfo.

**What they do not establish.** None of this has run against a live MOSIP deployment.

- The proof suites are verified against the reference **implementations** of those suites,
  not against a credential from a real Inji Certify instance.
- The eSignet client is verified against eSignet's **documented** behaviour, not against a
  live eSignet, which needs a registered client this repository's CI cannot hold.
- The IDA envelope is verified as **correct**; that MOSIP accepts *your* partner identity is
  not, and cannot be, because it needs a MISP licence key, partner id, API key and uploaded
  certificates.

This is the same boundary the Inji issuance profile has always stated, and it is drawn here
for the same reason: a conformance claim that cannot be reproduced by the reader is not a
claim, it is a hope. If you run any of this against a real MOSIP deployment — collab sandbox
or production — please open an issue with the result, including failures. Real-deployment
evidence is exactly what this section is waiting for.

**Not claimed anywhere:** MOSIP certification, compliance, or partnership. This is an
independent implementation of published interfaces.