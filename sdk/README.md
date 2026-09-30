# @openresidency/sdk

Millions of people cannot prove where they live, and lose access to services because of it.
[OpenResidency](https://github.com/Harmonizedx/open-residency) is open-source trust
infrastructure a state, province or county runs so that its residents can: it verifies a
person against the national ID, gives them a W3C Verifiable Credential that proves their
relationship with the jurisdiction, and lets every service (health, education, tax, social
protection) rely on that proof, online, offline, or over USSD. Each jurisdiction runs its own
instance and holds only its own relationships; a credential from one is recognised by any
other that trusts it. The national ID number never leaves the jurisdiction's server; what a
service receives is the credential and a tokenized reference.

This package is the typed client for one such instance. It is dependency-free, uses the
global `fetch` (Node 18+ or any browser), and every operation the server exposes is
reachable with its request and response types.

- API reference: [`docs/API.md`](https://github.com/Harmonizedx/open-residency/blob/main/docs/API.md)
  and the OpenAPI 3.1 description every instance serves at `/openapi.yaml` and `/docs`.
- Integrating a service: [`docs/INTEGRATION.md`](https://github.com/Harmonizedx/open-residency/blob/main/docs/INTEGRATION.md).
- Wallets and standards: [`docs/INTEROP.md`](https://github.com/Harmonizedx/open-residency/blob/main/docs/INTEROP.md).
- The specification the server implements is ORCS-001, the OpenResidency Core
  Specification. Section numbers below (ORCS §6, §7, §9, §10) refer to it.

```bash
npm install @openresidency/sdk
```

The package version is the server release: `@openresidency/sdk@0.2.0` is the client for
`v0.2.0`. Pin the version of the instance you integrate against. A newer client against an
older server will find some paths missing.

## Which one are you?

### A service checking whether someone is a resident

A clinic, a school, a bank, a subsidy desk. The citizen presents their credential (a QR code,
a wallet, a pasted token) and you ask the jurisdiction's instance whether it holds. No
credential of your own is needed.

```ts
import { OpenResidencyClient } from '@openresidency/sdk';

const jurisdiction = new OpenResidencyClient({ baseUrl: 'https://id.katsina.gov.ng' });

const check = await jurisdiction.verifyCredential(presentedJwt);
if (check.valid) {
  // check.subject carries the residency claims: jurisdiction, unit, assurance level.
} else {
  // check.reason says why: revoked, an issuer this instance does not trust, a bad or
  // expired signature, or a malformed token.
}
```

A credential issued by another jurisdiction verifies here too, if that jurisdiction is on this
instance's trust list. You do not need to know where a credential came from before checking it.

For verifiers without connectivity, `didDocument()` and `statusList(file)` fetch the issuer
keys and revocation lists an offline verifier caches while it has a connection, and
`qr(...)` renders a credential for paper carriage.

### A registrar, or a console for one

You verify a person against the national ID and issue, suspend, reinstate or revoke their
residency. These are operator actions: the client needs an operator key, minted at
`POST /operator/keys` by an operator who holds the role in question.

```ts
const jurisdiction = new OpenResidencyClient({
  baseUrl: 'https://id.katsina.gov.ng',
  operatorKey: process.env.OPERATOR_KEY, // ork_..., carries this operator's roles
});

const issued = await jurisdiction.issueResidency({
  countryCode: 'NG',
  subnationalUnit: 'KT',
  identifiers: { nin: '12345678901', dateOfBirth: '1990-01-01' },
});

switch (issued.status) {
  case 'issued':    // issued.residentId, issued.credentialJwt
  case 'exists':    // already registered; issued.residentId
  case 'challenge': // the ID source wants a second step; issued.challenge.channel
  case 'rejected':  // issued.reason, and issued.reference for the appeal
}

// The residency relationship's ORCS §6 state, and moving it
await jurisdiction.transitionRelationship(issued.residentId!, {
  status: 'SUSPENDED',
  reason: 'Address under review',
});

// Consent for a sector to read the record (ORCS §9), with a signed receipt
await jurisdiction.grantConsent({
  residentId: issued.residentId!,
  relyingParty: 'health',
  purpose: 'Enrol in state health scheme',
  scopes: ['residency', 'health'],
});
```

### A wallet, or a service that talks to wallets

The instance is an OpenID for Verifiable Credential Issuance (OpenID4VCI) issuer and an
OpenID for Verifiable Presentations (OpenID4VP) verifier. The methods are named after the
protocol steps: `credentialIssuerMetadata`, `createCredentialOffer`, `walletToken`,
`walletCredential`; `createPresentationRequest`, `submitPresentation`,
`presentationResult`. The W3C VC-API issuer and verifier interfaces are `vcIssue`,
`vcVerify` and `vpVerify`. Which dialects and proof types are accepted is in
[`docs/INTEROP.md`](https://github.com/Harmonizedx/open-residency/blob/main/docs/INTEROP.md).

## Outcomes are results, not exceptions

A refused application, an invalid credential or a transition the lifecycle does not permit
comes back as a normal return value with a reason: `issueResidency` returns
`status: 'rejected'` with a `reference` and, where the jurisdiction records one, an appeal
path; `verifyCredential` returns `valid: false` with a `reason`. Handle these in your
success path.

`OpenResidencyError` is thrown only for transport and authorisation failures: a non-2xx
response, carrying `status` and the parsed `body`. A 401 means no credential was accepted, a
403 means the operator lacks the role, a 400 means the request body was malformed or carried
a field the server does not declare.

## Credentials and roles

| Calls | Role needed | `auth` |
| --- | --- | --- |
| Verify a credential, read a relationship, credential or assurance, discovery documents, status lists | none | `'none'` or the default |
| Identity verification, issuance, reconcile, refusal review, credential offers, VC-API | `registrar` | operator key |
| Revoke, relationship and credential transitions | `revoker` | operator key |
| Consents, legal bases, resident listing, statistics, presentation requests | `support` | operator key |
| Erasure, retention and provisional sweeps, legal-basis withdrawal, operator accounts | `admin` | operator key |
| Audit log and chain verification | `auditor` | operator key |

Pass `operatorKey` for a machine caller, or `operatorToken` (the bearer token from an operator
sign-in) for a person in a console. `adminKey` is the deprecated shared key and works only on
deployments still configured for it. The named methods choose the right one; on `request`,
`auth` is `'auto'` (send the configured credential), `'operator'` (require one),
`'none'`, `{ bearer }` for a one-off token such as the OpenID4VCI access token, or
`{ headers }` for a one-off header such as `x-ussd-secret`.

## Every operation

The named methods cover the integrator-facing surface:

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

`request` reaches every operation in the server's OpenAPI description, including the ones with
no named method (the browser-driven OIDC login interaction, WebAuthn registration, the upstream
enrolment callback). The path is a string literal from the description; its parameters, body
and response are typed:

```ts
const credential = await jurisdiction.request('get', '/residency/{residentId}/credential', {
  path: { residentId: 'KT-GT1F-75WJ-6' },
});

const page = await jurisdiction.request('get', '/admin/residents', {
  query: { countryCode: 'NG', limit: 50 },
  auth: 'operator',
});
```

`paths` and `components` are exported, so any request or response type can be named:

```ts
import type { components } from '@openresidency/sdk';
type Relationship = components['schemas']['RelationshipStatus'];
```

## Trust the package

Every version after 0.1.0 is built and published by the repository's release workflow through
npm trusted publishing. The registry page names the commit and workflow run that produced the
tarball, and `npm audit signatures` verifies the attestation locally. The client's types are
generated from the server's OpenAPI description, and the repository's CI fails if that
description misses a route the server declares or if the generated types are stale, so what
the client can call is what the server serves.

## Project

- Licence: Apache-2.0.
- Security reports: privately, per [`SECURITY.md`](https://github.com/Harmonizedx/open-residency/blob/main/SECURITY.md). Please do not open a public issue for a vulnerability.
- Contributing and code of conduct: [`CONTRIBUTING.md`](https://github.com/Harmonizedx/open-residency/blob/main/CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](https://github.com/Harmonizedx/open-residency/blob/main/CODE_OF_CONDUCT.md).
- Governance: [`GOVERNANCE.md`](https://github.com/Harmonizedx/open-residency/blob/main/GOVERNANCE.md).
