# Integrating a service with OpenResidency

This guide is for a team that already runs a platform — a ministry service, an education or
health portal, a payments or permits system — and wants to use OpenResidency for **identity and
authentication** without rebuilding their app around it.

The central idea: **you do not merge databases.** Your platform keeps its own users and its own
business logic. OpenResidency gives you a trustworthy, consented answer to "who is this person and
where do they reside," and you link that answer to your existing account **once, at first
authentication**. After that, every future login is recognized.

There are three integration paths. They compose — most services use **A** for login and **C** for
backend re-checks.

---

## The account-linking model (why "no correlation" is fine)

Your users have no pre-existing link to the resident registry, and they don't need one. Every
authenticated citizen carries a stable `resident_id`. On the first login you decide how to bind it:

```
first login  ->  do we already have this resident_id?
                   ├─ yes -> log into the existing local account
                   └─ no  -> create a local account, OR bind to an existing one
                             (match on a consented email/phone claim, or have the
                              user sign in once with their old credentials to confirm)
                 store mapping:  local_user_id  <->  resident_id
later logins ->  resident_id -> local account, directly
```

`resident_id` is your join key. Nothing else about your schema changes.

---

## Path A — Sign in with State (OpenID Connect)

The primary path for a web or mobile platform that wants login + identity. OpenResidency is a
standards OIDC Identity Provider, so you integrate with **any off-the-shelf OIDC library** — nothing
OpenResidency-specific runs in your app.

### 1. Register your service as a relying party (YAML, no code change)

Add an entry under `oidc.relyingParties` in the jurisdiction's config in `config/countries/`:

```yaml
oidc:
  relyingParties:
    - clientId: ktsg_scholarship            # stable; also names the secret env var
      name: Katsina Scholarship Board       # shown to the citizen on the consent screen
      sector: education                      # becomes a scope; add a sector without code
      redirectUris:
        - https://scholarship.kt.gov.ng/auth/callback
      postLogoutRedirectUris:
        - https://scholarship.kt.gov.ng/
```

The client secret is **never** in the file. It is read from an environment variable named
`<CLIENTID>_CLIENT_SECRET`, where `<CLIENTID>` is the `clientId` uppercased — here
`KTSG_SCHOLARSHIP_CLIENT_SECRET`. (Choose a `clientId` without hyphens so the env var name is
clean.) Adding a new `sector` here registers it as a requestable scope automatically — no code
change.

### 2. Client facts to configure your OIDC library

| Setting | Value |
|---|---|
| Discovery | `GET /oidc/.well-known/openid-configuration` |
| Flow | Authorization Code + **PKCE** (PKCE is required) |
| `response_type` | `code` |
| `grant_types` | `authorization_code`, `refresh_token` |
| Token auth method | `client_secret_basic` |
| Scopes to request | `openid profile residency education` (swap your sector) |
| Issuer DID document | `GET /.well-known/did.json` |

### 3. Claims you receive

The ID token / userinfo carries **only** these, and **never the national ID number**:

| Scope | Claims |
|---|---|
| `openid` | `sub` (currently equal to `resident_id`) |
| `profile` | `name`, `given_name`, `family_name`, `birthdate`, `gender` |
| `residency` | `resident_id`, `country_code`, `subnational_unit`, `assurance_level`, `provisional` |

The citizen logs in once at the state IdP and **consents per service**; consent is a first-class,
revocable record and is written to the tamper-evident audit log.

### 4. Minimal callback (Node, `openid-client`)

```js
import { Issuer, generators } from 'openid-client';

const issuer = await Issuer.discover('https://id.kt.gov.ng/oidc');
const client = new issuer.Client({
  client_id: 'ktsg_scholarship',
  client_secret: process.env.KTSG_SCHOLARSHIP_CLIENT_SECRET,
  redirect_uris: ['https://scholarship.kt.gov.ng/auth/callback'],
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
});

// --- start login ---
const code_verifier = generators.codeVerifier();
req.session.cv = code_verifier;
const url = client.authorizationUrl({
  scope: 'openid profile residency education',
  code_challenge: generators.codeChallenge(code_verifier),
  code_challenge_method: 'S256',
});
res.redirect(url);

// --- callback ---
const params = client.callbackParams(req);
const tokenSet = await client.callback(
  'https://scholarship.kt.gov.ng/auth/callback',
  params,
  { code_verifier: req.session.cv },
);
const c = tokenSet.claims();          // { sub, resident_id, subnational_unit, assurance_level, ... }

// --- account linking (the one bit that is yours) ---
let user = await db.users.findByResidentId(c.resident_id);
if (!user) user = await db.users.create({ resident_id: c.resident_id, name: c.name });
req.session.userId = user.id;         // logged in
```

That "account linking" block is the only OpenResidency-aware code in your app.

---

## Path B — Credential presentation (OpenID4VP)

Use this when the citizen holds their residency credential in a wallet (Inji / OpenWallet), or for
in-person and low-connectivity checks where a browser redirect is impractical. Your service acts as
a **verifier**:

1. Build an OpenID4VP request for a residency credential.
2. The wallet presents the VC.
3. You verify the signature and revocation status **offline**, against the issuer's DID document and
   the cached Bitstring Status List — no callback to OpenResidency needed.

Because verification is cryptographic and offline, this works air-gapped and at the edge. See
[`INTEROP.md`](INTEROP.md) for the request/response shapes and wallet compatibility notes.

---

## Path C — Backend verification API

For server-to-server checks, typically **alongside** Path A — e.g. re-confirm residency at the
moment a scholarship is awarded, not just at login.

| Call | Purpose |
|---|---|
| `POST /residency/verify` `{ credential, offline }` | Validate a VC-JWT: signature, expiry, revocation |
| `GET /residency/{residentId}` | Current, non-sensitive residency status |

With the typed SDK ([`SDK.md`](SDK.md)):

```js
import { OpenResidencyClient } from '@openresidency/sdk';
const or = new OpenResidencyClient({ baseUrl: 'https://id.kt.gov.ng' });

const outcome = await or.verifyCredential(credentialJwt);   // POST /residency/verify
const status  = await or.residencyStatus('KT-7F3A-9K2P-4'); // GET  /residency/{id}
```

Full API surface: [`API.md`](API.md) and the OpenAPI spec at `/openapi.yaml` (`/docs`).

---

## What OpenResidency does NOT decide for you

A residency login proves **who** the person is and **that they reside** in the jurisdiction. It does
**not** prove **entitlement**. Your service keeps its own eligibility rules and runs them over the
claims it receives:

```
OpenResidency  ->  verified identity + residency claims   (the input)
Your platform  ->  "is this a registered student, in the age band,
                    resident >= 12 months?"               (your business logic)
```

This is deliberate — the Layer 3 (credential) → Layer 4 (eligibility) separation described in
[`RESIDENCY-POLICY.md`](RESIDENCY-POLICY.md). You inherit identity and residency assurance; you do
not surrender your domain logic.

---

## Before you go live — checklist

- [ ] **OTP delivery.** Sign-in binds a real factor (Verifiable Presentation primary, one-time
      code fallback; a bare ResidentID does not authenticate). Delivery is now configured, not
      stubbed: set a `messaging` block (Africa's Talking, Twilio, Termii, or any REST aggregator
      via `GENERIC_HTTP`) and a `contactDirectory`. Omit them and the fallback is switched off;
      `provider: LOG` still prints codes and refuses to boot without an explicit acknowledgement.
- [ ] **Cross-service correlation.** The OIDC `sub` is now **pairwise** by default — each relying
      party sees a different, stable identifier for the same citizen, derived under the deployment
      pepper. Plan for this: your service's `sub` will not match any other service's, which is the
      point. The correlatable `resident_id` claim comes from the `residency` scope, which is
      granted per relying party in config and is **not** given to every RP any more. If your
      integration reads `resident_id`, ask for that scope explicitly and be ready to justify it.
- [ ] **Secrets.** Set `<CLIENTID>_CLIENT_SECRET` from your secret store. There is no dev fallback
      any more — the app refuses to start if one is missing.
- [ ] **Redirect URIs.** Register the exact production callback URLs; no wildcards.
- [ ] **Consent & data protection.** Request the narrowest scope set you need, and confirm the
      lawful basis for the claims you consume with the identity authority.
- [ ] **Token handling.** Validate the ID token signature against the IdP JWKS, check `aud`/`iss`,
      and store only what you need (ideally just the `resident_id` mapping).
