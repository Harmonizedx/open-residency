# Interoperability

OpenResidency issues and verifies credentials using the same standards the rest of the
digital identity ecosystem uses. The goal is that a residency credential is not a
special thing that only our software understands — it is a W3C Verifiable Credential,
obtained over OpenID4VCI and presented over OpenID4VP, which any compatible wallet or
relying party can handle without writing a line of OpenResidency-specific code.

This document records what we implement, what we deliberately do not, and the
compromises we made to interoperate with wallets as they actually exist rather than as
the specifications describe them.

## What we implement

| Standard | Version | Where |
|---|---|---|
| [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/) | 2.0 | `src/core/credentials/` |
| [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/) | 1.0 | `src/core/credentials/status-list.ts` |
| [VC Data Integrity — `eddsa-rdfc-2022`](https://www.w3.org/TR/vc-di-eddsa/) | 1.0 | `src/core/credentials/ldp-issuer.ts` |
| [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | 1.0 **and** Draft 13 | `src/core/oid4vci/` |
| [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | 1.0 | `src/core/oid4vp/` |

## Credential formats

We issue the same credential in two formats. They carry identical claims — both are
built by one function, `buildCredentialBody`, precisely so they cannot drift apart — and
they share a single revocation bit, so revoking a resident revokes every credential ever
issued to them, in any format, in any wallet.

**`ldp_vc`** — JSON-LD with a Data Integrity proof. This is what wallets want. It is the
format Inji accepts, and the default for the OpenID4VCI flow.

**`jwt_vc_json`** — a W3C VC packed into a signed JWT. This remains the right format for
the offline path: it is compact enough to print in a QR code and needs no JSON-LD
canonicalization to verify, so a field officer's phone can check a credential with no
network and no heavy toolchain. It is what `POST /residency/issue` returns and what the
offline QR carries.

## The pre-authorized code flow, and why it fits

OpenID4VCI defines two grants. We implement only the pre-authorized code grant, because
it is the one that matches how residency enrollment physically happens:

1. A citizen presents themselves at an enrollment desk. An operator verifies them against
   the foundational ID — NIN, Aadhaar, whatever the country config declares. This is the
   existing `POST /residency/issue`, unchanged.
2. The desk calls `POST /openid4vci/offer` and shows the returned QR code, reading out a
   6-digit transaction code.
3. The citizen scans it with their own wallet. The wallet redeems the code, proves it
   holds a key on the device, and receives a credential bound to that key.

There is no authorization-code flow because there is nothing to authorize interactively.
The citizen was already authenticated, in person, against their national ID.

### Why the key proof is mandatory

The credential endpoint refuses to issue without a key proof. This is the single most
important security property of the OpenID4VCI path, and it is worth being explicit about
what it fixes.

Before this, `POST /residency/issue` would mint a credential whose subject was
`urn:resident:KT-7F3A-9K2P` when no holder was supplied. Nothing bound that credential to
anyone. Whoever held the bytes could present it — it was a bearer token wearing the
costume of a credential. Now the subject is a DID derived from a key the wallet proved it
controls, and presenting the credential (over OpenID4VP) requires signing over a fresh
verifier nonce. Possession of the credential is no longer sufficient to use it.

### Offer security

The Credential Offer is passed **by value**: the pre-authorized code travels inside the
QR code rather than being fetched from us. That means we store only `sha256(code)`, and a
dump of the `CredentialOffer` table yields nothing redeemable.

The cost is that the code is now visible to anyone who photographs the screen. Three
things make that acceptable, and all three are tested in `scripts/oid4vci-smoke.ts`:

- the transaction code is a **second factor** and is *not* in the QR — it is spoken aloud;
- the pre-authorized code is **single-use** and expires after 15 minutes;
- wrong transaction codes are **counted**, and the offer locks after five, so a 6-digit
  PIN cannot be brute-forced.

## Compromises made for real wallets

The specifications and the deployed wallets disagree. Where they do, we chose to work
with the wallets, and marked every such place in the code. These are the compromises.

### We speak two versions of OpenID4VCI at once

OpenID4VCI reached Final 1.0 in September 2025. MOSIP's Inji — the wallet this project
most wants to serve, and the reference wallet of the OpenWallet ecosystem — still
implements Draft 13. The two are wire-incompatible:

| | Draft 13 (Inji) | Final 1.0 |
|---|---|---|
| Key proof | `proof` (singular object) | `proofs` (plural, arrays) |
| Credential response | `credential` | `credentials: [{credential}]` |
| `c_nonce` source | the token response | a dedicated Nonce Endpoint |
| Request identifies credential by | `format` + `credential_definition` | `credential_configuration_id` |
| Claims/display metadata | top-level | nested under `credential_metadata` |

Implementing only 1.0 would produce a technically correct issuer that no current wallet
can use. So the credential endpoint detects which dialect a request is written in and
answers in the same one, and the metadata document emits both spellings of claims and
display. When Draft 13 wallets age out, deleting these should be mechanical — they are
all commented.

### The access token is a JWT carrying `c_nonce` and `client_id`

This one is not in *any* version of the spec.

Inji's VCI client does not read `c_nonce` from the token response body. It parses the
access token as a JWT and reads `c_nonce` and `client_id` out of the claims *inside* it:

```kotlin
val jwtClaimsSet = JWTParser.parse(accessToken).jwtClaimsSet
JWTProofPayload(jwtClaimsSet.getClaim("client_id").toString(),
                jwtClaimsSet.getClaim("c_nonce").toString(), ...)
```

If those claims are absent, the wallet signs its key proof with the literal string
`"null"` as the nonce, we correctly reject the proof, and the citizen sees "enrollment
failed" with no way to diagnose it. This is an eSignet implementation detail that leaked
into the wallet, but the cost of accommodating it is one duplicated claim, and the cost of
not accommodating it is that the wallet does not work. So our access tokens are signed
JWTs that carry both claims. Spec-compliant wallets never look inside and are unaffected.

### We advertise RS256

Inji hardcodes `RS256` in its key-proof generator. We would not choose RSA — EdDSA keeps
credentials small, which matters for QR codes — but refusing RS256 means refusing the
wallet. So `proof_signing_alg_values_supported` lists `EdDSA`, `ES256`, and `RS256`, and
EdDSA is what we recommend.

A consequence: an RSA holder key cannot be encoded as a `did:key` (the multicodec
registration is impractical), so RSA holders are bound via **`did:jwk`** instead, which
carries the key inline. Ed25519 holders get a `did:key`. Both resolve with no network
access, which is the property we actually care about — an offline verifier can recover the
holder's key from the credential itself.

### We tolerate `iss` and `exp` in key proofs

The spec says `iss` MUST be omitted from a key proof in the anonymous pre-authorized flow.
Inji sends it anyway, and also adds a non-standard `exp`. Neither is a claim we rely on,
so rejecting on those grounds would break the wallet for no security benefit. We ignore
`iss` and honour `exp` if present.

## JSON-LD contexts are pinned, never fetched

Canonicalizing a JSON-LD credential requires dereferencing every `@context` it declares.
We refuse to do that over the network. `staticDocumentLoader` resolves contexts from
pinned copies in `contexts/` and throws on anything it does not already hold.

This is not an optimization; it is three correctness properties:

- **Determinism.** A signature covers the canonical form of the document. If a context is
  fetched at signing time and again at verification time and changed in between, the
  signature silently stops verifying.
- **Availability.** A verifier at a rural clinic has no internet. Requiring an HTTP
  round-trip to `w3.org` to check a residency card defeats the entire point.
- **Integrity.** A remote context is an *input* to what the signature covers. Whoever
  serves it can influence how claims are interpreted.

Canonicalization also runs in **safe mode**, which turns "this term is not defined in any
context" from a silent drop into a thrown error. Without it, a claim we forgot to define
would vanish from the canonical form — and therefore from what the signature covers — while
the credential still verified. The document would attest less than it appears to. That is
a forgery vector, not a formatting nit, and it is why `contexts/residency-v1.jsonld`
exists and defines every custom term we use.

## Adding a wallet

If a wallet cannot complete issuance against this deployment, the fastest way to find out
why is `scripts/oid4vci-smoke.ts`, which drives the whole flow from the wallet's side in
both dialects. Add a case there that reproduces the wallet's behaviour, watch it fail, and
fix the issuer. Please do not fix it by relaxing the key-proof, nonce, or audience checks;
those are load-bearing.
