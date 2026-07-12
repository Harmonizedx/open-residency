# @openresidency/sdk

Typed client for the OpenResidency API. Dependency-free, uses the global `fetch`
(Node 18+ or any browser). Every method maps to an endpoint in `docs/openapi.yaml`.

## Install

```bash
npm install @openresidency/sdk
```

## Use

```ts
import { OpenResidencyClient } from '@openresidency/sdk';

const client = new OpenResidencyClient({ baseUrl: 'https://id.katsina.gov.ng' });

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

// Consent
await client.grantConsent({
  residentId: issued.residentId!,
  relyingParty: 'health',
  purpose: 'Enrol in state health scheme',
  scopes: ['residency', 'health'],
});
const consents = await client.listConsents(issued.residentId!);
```

## Admin endpoints

Pass `adminKey` to reach the registry and audit endpoints:

```ts
const admin = new OpenResidencyClient({
  baseUrl: 'https://id.katsina.gov.ng',
  adminKey: process.env.ADMIN_API_KEY,
});
const chain = await admin.verifyAuditChain(); // { ok: true, length: N }
const page = await admin.listResidents({ countryCode: 'NG', limit: 50 });
```

## Errors

Non-2xx responses throw `OpenResidencyError` with `status` and parsed `body`.

## Build

```bash
npm run build
```

Licensed under Apache-2.0.
