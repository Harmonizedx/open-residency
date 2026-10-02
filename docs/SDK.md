# Interoperability SDK

A typed, dependency-free client lives in `sdk/` and is on npm as
[`@openresidency/sdk`](https://www.npmjs.com/package/@openresidency/sdk). It reaches every
operation in `docs/openapi.yaml`, so sector services and partners integrate without
hand-writing HTTP.

```bash
npm install @openresidency/sdk
```

The package version is the release tag: `@openresidency/sdk@0.1.0` is the client for the
`v0.1.0` release, and the release workflow refuses to publish a version that differs from
the tag. Pin the same version as the server you integrate against. Versions after 0.1.0
are published by the release workflow through npm trusted publishing and carry provenance,
so the registry page names the commit and workflow run that built the tarball; 0.1.0 was
published by hand and has none.

## How it stays in step with the server

The client's types are generated from `docs/openapi.yaml` into `sdk/src/openapi.ts`
(`npm run sdk:generate`) and committed. Two CI checks hold the chain together:

- `npm run lint:openapi` reads every `@Controller` and `@Get`/`@Post` decorator in `src/` and
  fails if a route is missing from the spec, or the spec names a route no controller serves.
- The generated file is regenerated in CI and must match what is committed.

So a route cannot be added to the server without being documented, and cannot be documented
without reaching the SDK. Before these checks the spec had drifted to 43 of 80 routes, and
the ORCS relationship and credential lifecycle was invisible to anyone integrating through it.

## Before the client is useful

It needs an instance. A jurisdiction with no KMS and no national ID API stands one up from a
register extract in [`FIRST-RESIDENCY.md`](FIRST-RESIDENCY.md).

## Use

See `sdk/README.md` for the full method table. Quick example:

```ts
import { OpenResidencyClient } from '@openresidency/sdk';

const client = new OpenResidencyClient({
  baseUrl: 'https://id.katsina.gov.ng',
  operatorKey: process.env.OPERATOR_KEY,
});

const issued = await client.issueResidency({
  countryCode: 'NG',
  subnationalUnit: 'KT',
  identifiers: { nin: '12345678901', dateOfBirth: '1990-01-01' },
});

const check = await client.verifyCredential(issued.credentialJwt!);
const relationship = await client.relationship(issued.residentId!);
```

Anything without a named method is one `request` call, typed from the spec:

```ts
const result = await client.request('get', '/openid4vp/result/{id}', { path: { id } });
```

Audit and registry calls take an operator credential:

```ts
const integrity = await client.verifyAuditChain(); // { ok, length, anchored, ... }
```

Because the SDK is generated from the OpenAPI contract, clients for other languages
(Python, Go, Java) come from running your preferred OpenAPI generator against
`docs/openapi.yaml`, and cover the same surface.
