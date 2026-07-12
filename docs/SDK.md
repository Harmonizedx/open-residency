# Interoperability SDK

A typed, dependency-free client lives in `sdk/` and is published as
`@openresidency/sdk`. It mirrors `docs/openapi.yaml` one-to-one, so sector services
and partners integrate without hand-writing HTTP.

See `sdk/README.md` for full usage. Quick example:

```ts
import { OpenResidencyClient } from '@openresidency/sdk';

const client = new OpenResidencyClient({ baseUrl: 'https://id.katsina.gov.ng' });

const issued = await client.issueResidency({
  countryCode: 'NG',
  subnationalUnit: 'KT',
  identifiers: { nin: '12345678901', dateOfBirth: '1990-01-01' },
});

const check = await client.verifyCredential(issued.credentialJwt!);
```

Admin and audit calls take an `adminKey`:

```ts
const admin = new OpenResidencyClient({ baseUrl, adminKey: process.env.ADMIN_API_KEY });
const integrity = await admin.verifyAuditChain(); // { ok, length }
```

Because the SDK is generated against the OpenAPI contract, regenerating clients for
other languages (Python, Go, Java) is a matter of running your preferred OpenAPI
generator against `docs/openapi.yaml`.
