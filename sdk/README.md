# @openresidency/sdk

Typed client for the OpenResidency API. Dependency-free, uses the global `fetch`
(Node 18+ or any browser).

The client reaches the whole API. Its types are generated from `docs/openapi.yaml`
(`sdk/src/openapi.ts`, regenerated with `npm run sdk:generate` at the repository root), and
CI fails if the spec misses a route the server declares or if the generated file is stale.
So what the client can call is what the server serves, by construction.

## Install

```bash
npm install @openresidency/sdk
```

Pin the version to the server release you integrate against; `@openresidency/sdk@0.1.0` is
the client for `v0.1.0`.

## Two ways in

**Named methods** cover what a sector service, a wallet backend or a registry console calls,
and pick the right credential for each:

```ts
import { OpenResidencyClient } from '@openresidency/sdk';

// Identity verification and issuance are operator actions, so the client needs a credential.
const client = new OpenResidencyClient({
  baseUrl: 'https://id.katsina.gov.ng',
  operatorKey: process.env.OPERATOR_KEY, // ork_..., minted at POST /operator/keys
});

// Verify a person against the national ID (no residency issued)
const idv = await client.verifyIdentity({
  countryCode: 'NG',
  identifiers: { nin: '12345678901', dateOfBirth: '1990-01-01' },
  purpose: 'health enrolment',
});

// Issue a residency credential
const issued = await client.issueResidency({
  countryCode: 'NG',
  subnationalUnit: 'KT',
  identifiers: { nin: '12345678901', dateOfBirth: '1990-01-01' },
});
console.log(issued.residentId, issued.credentialJwt);

// Verify a presented credential (a sector service checking a citizen's residency)
const check = await client.verifyCredential(issued.credentialJwt!);
console.log(check.valid, check.subject);

// The relationship's ORCS state, and moving it
const rel = await client.relationship(issued.residentId!);
await client.transitionRelationship(issued.residentId!, {
  status: 'SUSPENDED',
  reason: 'Address under review',
});

// Consent
await client.grantConsent({
  residentId: issued.residentId!,
  relyingParty: 'health',
  purpose: 'Enrol in state health scheme',
  scopes: ['residency', 'health'],
});
const consents = await client.listConsents(issued.residentId!);
```

**`request`** reaches every operation in the spec, including the ones with no named method.
The path is a string literal from the spec; its parameters, body and response are typed:

```ts
const credential = await client.request('get', '/residency/{residentId}/credential', {
  path: { residentId: 'KT-GT1F-75WJ-6' },
});

const page = await client.request('get', '/admin/residents', {
  query: { countryCode: 'NG', limit: 50 },
  auth: 'operator',
});
```

`auth` is `'auto'` by default (the configured operator credential, if any), `'operator'` to
require one, `'none'` to send nothing, `{ bearer }` for a one-off token such as the
OpenID4VCI access token, or `{ headers }` for a one-off header such as `x-ussd-secret`.

## What the named methods cover

| Area | Methods |
| --- | --- |
| Health | `live`, `ready` |
| Identity | `identityChallenge`, `verifyIdentity` |
| Residency | `countries`, `issueResidency`, `residencyStatus`, `verifyCredential`, `revokeResidency`, `eraseResidency`, `retentionSweep`, `provisionalSweep`, `reconcile` |
| Relationship and credential lifecycle (ORCS §6, §10) | `relationship`, `transitionRelationship`, `credential`, `transitionCredential`, `refusal`, `reviewRefusal` |
| Assurance (ORCS §7) | `assuranceProfiles`, `assuranceMappings`, `resolveAssurance`, `residentAssurance` |
| Consent and legal bases (ORCS §9) | `listConsents`, `grantConsent`, `revokeConsent`, `legalBases`, `legalBasis`, `deactivateLegalBasis` |
| Operator identity | `operatorLogin`, `me`, `listOperators`, `createOperator`, `disableOperator`, `listKeys`, `createKey`, `rotateKey`, `revokeKey` |
| Audit and admin | `auditLog`, `verifyAuditChain`, `listResidents`, `stats`, `statistics`, `statisticsCsv` |
| Offline | `qr`, `ussd` |
| OpenID4VCI (issuing into a wallet) | `credentialIssuerMetadata`, `oauthAuthorizationServerMetadata`, `createCredentialOffer`, `walletToken`, `walletNonce`, `walletCredential` |
| OpenID4VP (asking a wallet to present) | `createPresentationRequest`, `presentationRequest`, `submitPresentation`, `presentationResult` |
| W3C VC-API | `vcIssue`, `vcVerify`, `vpVerify` |
| Discovery and trust | `didDocument`, `didDocumentFor`, `statusList`, `oidcDiscovery` |

The OIDC login interaction (`/interaction/{uid}/...`), WebAuthn registration and the upstream
enrolment callback are browser-driven and have no named method. `request` reaches them.

## Types

`paths` and `components` are exported from the generated contract, so a caller can name
any request or response type:

```ts
import type { components } from '@openresidency/sdk';
type Relationship = components['schemas']['RelationshipStatus'];
```

The hand-written interfaces the 0.1.0 methods return (`IssueResult`, `ResidencyStatus`,
`ConsentRecord`, ...) are unchanged.

## Errors

Non-2xx responses throw `OpenResidencyError` with `status` and parsed `body`.

## Build

```bash
npm run build
```

Licensed under Apache-2.0.
