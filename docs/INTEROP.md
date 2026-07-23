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

## Presenting a credential (OpenID4VP)

A relying party — a clinic, a subsidy desk, a bank — opens a presentation request, shows
the citizen a QR, and gets back a verified answer. It does not integrate anything
OpenResidency-specific to do that.

```
POST /openid4vp/request        (relying party, admin key)  -> openid4vp:// URI + QR
GET  /openid4vp/request/:id    (wallet)                    -> signed Request Object
POST /openid4vp/response/:id   (wallet, direct_post)       -> vp_token
GET  /openid4vp/result/:id     (relying party, admin key)  -> the verdict
```

The Request Object is **signed**, so the wallet can tell the citizen who is actually
asking before they consent. An unsigned request would let anything capable of displaying
a QR code impersonate a hospital and harvest residency data.

We emit **both** a `dcql_query` (OpenID4VP 1.0) and a `presentation_definition`
(Presentation Exchange). Wallets are mid-migration between the two, so emitting both means
we do not have to guess which one a given wallet speaks.

### Verifying a presentation is not verifying a credential

This distinction is the entire reason OpenID4VP exists, and it is worth stating plainly.

The old `POST /residency/verify` takes a raw VC-JWT and checks that the issuer signed it,
that it has not expired, and that it is not revoked. **Every one of those checks passes for
a credential copied from somebody else.** It answers "is this a genuine credential?" — never
"is the person in front of me its holder?", and never "was this presented to *me*, *just
now*?".

`VpVerifier` enforces four things, and dropping any one of the first three collapses the
credential back into a bearer token:

1. **Holder binding** — the presentation is signed by the key named in the credential's
   `credentialSubject.id`. A stolen credential presented under a different key is refused.
2. **Freshness** — the nonce is one we just issued, and the request is single-use. A
   captured presentation cannot be replayed at us a second time.
3. **Audience** — `aud` is us. A presentation captured by a shop cannot be replayed by that
   shop at a hospital.
4. **Credential validity** — signature, expiry, and revocation, delegated to the existing
   verifiers.

`scripts/oid4vp-smoke.ts` runs each of these attacks and asserts it is rejected *for the
right reason*.

### The presentation path fails closed on revocation

`VcVerifier` is deliberately permissive when it cannot reach a status list: it returns
`valid: true` with `checkedRevocation: false`, so a field officer with no connectivity can
still check a card against their last synced snapshot and know exactly what they are
getting. That is correct for offline verification.

It is **not** correct online. `VpVerifier` runs on a server that has just synced the status
list; if there is no list to check against, something is wrong. "Accept it anyway, but set
a flag" means a revoked credential is accepted by every relying party that does not read
the flag — and nobody reads the flag. So a presentation with an uncheckable revocation
status is **refused** (`REVOCATION_UNCHECKABLE`).

### Only the claims that were asked for are released

The residency credential carries `foundationalAssurance.subjectRef` — the tokenized
reference to the person's national ID — and their date of birth. A clinic confirming
residency has no business receiving either, and `subjectRef` is precisely the field the
whole tokenization design exists to protect. `minimizeClaims` releases the residency ID,
the subnational unit, the name, and the provisional flag. Nothing else leaves.

## What "Inji-compatible" is verified against — and what it is not

Every Inji-specific behavior described above is drawn from Inji's **published client
source** (the `c_nonce`-from-access-token reading is the Kotlin quoted earlier), not from
guesswork. `npm run smoke:inji` turns those into an executable contract: a wallet that
behaves exactly as Inji's documented code does drives the real issuer, and each
accommodation is asserted — including a **negative test that proves each is load-bearing**.
The sharpest is the `c_nonce` one: with `cNonceInAccessToken` off, the conformance wallet
finds no `c_nonce` claim, signs its proof over the literal string `"null"` (Kotlin's
`null.toString()`), and the issuer rejects it — reproducing the exact "enrollment failed"
a real Inji user would hit. That is why the accommodation exists, and the test fails if it
is ever removed.

The honest boundary: this verifies the issuer against Inji's **documented** behavior, not
the **live Inji app**. Confirming the real mobile wallet against a MOSIP stack is a
device-level test this repo's CI cannot run; if Inji's real behavior ever diverges from its
published source, only that would catch it. Everything up to that line is pinned.

## Wallet profiles: this is configuration, not code

A recurring question: **is this built for Inji?** No. The implementation speaks the
standards and sniffs no wallet — there is no `if (wallet === 'inji')` anywhere in the
codebase. Inji is simply the *hardest* wallet to satisfy, so satisfying it means satisfying
the others.

What we do is offer the **union** of what wallets need, and the union is configurable per
country in `config/countries/*.yaml`:

```yaml
wallet:
  formats: [ldp_vc, jwt_vc_json]
  proofAlgs: [EdDSA, ES256, RS256]
  compatibility:
    draft13: true
    cNonceInAccessToken: true
  offer:
    ttlSeconds: 900
    txCodeLength: 6
    maxTxCodeAttempts: 5
  accessTokenTtlSeconds: 600
  nonceTtlSeconds: 300

presentation:
  requestTtlSeconds: 300
  query: [dcql, presentation_definition]
```

Every value above is the default. **Omit the blocks entirely and you get exactly this** —
which is what `ng.yaml`, `in.yaml`, and `ke.yaml` do.

### What each knob costs you

| Knob | Default | Why you might change it |
|---|---|---|
| `formats` | both | Inji rejects `jwt_vc_json`; `jwt_vc_json` is the offline/QR path. Drop one only if you are sure you need neither. |
| `proofAlgs` | EdDSA, ES256, RS256 | **RS256 is present only because Inji hardcodes it.** Drop it when your wallets move on — EdDSA keeps credentials small, which is what keeps the QR scannable. |
| `compatibility.draft13` | `true` | Draft 13 and 1.0 are wire-incompatible. Turning this off **rejects** Draft 13 requests, narrowing the accepted surface. A security improvement once your wallets are on 1.0. |
| `compatibility.cNonceInAccessToken` | `true` | Not in **any** version of the spec. Exists solely because Inji reads `c_nonce` from *inside* the access token. If you do not serve Inji, turn it off rather than emit a non-standard claim for nobody's benefit. |
| `offer.txCodeLength` | 6 | The spoken second factor. Longer is stronger, and harder to read out over a noisy counter. |
| `offer.maxTxCodeAttempts` | 5 | A short numeric PIN is **only** safe because guesses are bounded. Raising this materially weakens the second factor. |
| `presentation.query` | both | DCQL is 1.0; Presentation Exchange is what wallets mid-migration use. Emitting both means not guessing. |

### The knobs are load-bearing, not decorative

It would be easy to add config that is read but never enforced. `scripts/oid4vci-smoke.ts`
runs a **strict profile** (`ldp_vc` only, EdDSA only, `draft13: false`,
`cNonceInAccessToken: false`, 8-digit PIN) and asserts that it genuinely narrows behaviour:

- an **RS256 key proof is rejected**
- a **Draft 13 request is rejected**
- the non-standard `c_nonce`/`client_id` claims are **absent** from the access token
- only `ldp_vc` appears in the issuer metadata
- and a spec-current 1.0 wallet **still works**

### Recommendation

Start on the defaults; they interoperate with everything, including Inji. Move to the
strict profile as soon as the wallets you actually serve are on OpenID4VCI 1.0. Narrowing
is a security improvement — a smaller request surface and no non-standard claims — so it is
worth revisiting, not something to set once and forget.

## Sign-in ("Sign in with <State>")

The residency system is also an OpenID Connect identity provider: sector services
authenticate citizens through it and receive only the residency claims the citizen
consents to release, never the national ID. Sign-in offers two factors.

**Primary — Verifiable Presentation.** The citizen scans a QR and presents their residency
credential from a wallet, over the same OpenID4VP path the rest of the platform uses. That
proves holder binding, freshness, and audience, so the residency ID that comes back is
*authenticated*, and a revoked credential is refused at sign-in exactly as it is at a
clinic.

**Fallback — one-time code.** For a citizen whose wallet is not to hand. The code lifecycle
is real and enforced (single-use, expiring, attempt-bounded), but **delivery is delegated**:
`OtpService` never sees a phone number. OpenResidency deliberately does not store plaintext
contact details — the schema keeps only a `phoneHash` — so an `OtpSender` implemented by the
deployment, against its own SMS gateway and contact directory, does the sending. The
`messaging.provider: LOG` logs the code and is for development only; a production
deployment MUST replace it.

> This replaced a login handler that authenticated anyone who could name an *existing*
> residency ID. Residency IDs are semi-public (printed on cards, carried in QR codes), so
> that was not authentication — it was an open door to every citizen's cross-sector session.
> `scripts/sso-smoke.ts` asserts the door is shut: a stolen credential, a revoked
> credential, and a bare residency ID all fail to sign in.

## Adding a wallet

If a wallet cannot complete issuance against this deployment, the fastest way to find out
why is `scripts/oid4vci-smoke.ts`, which drives the whole flow from the wallet's side in
both dialects. Add a case there that reproduces the wallet's behaviour, watch it fail, and
fix the issuer. Please do not fix it by relaxing the key-proof, nonce, or audience checks;
those are load-bearing.
