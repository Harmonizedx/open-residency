# Your first residency credential, with nothing but a spreadsheet

For a state, province or county that has **no HSM or cloud KMS** and **no national ID API to
call**: just an extract of the residents' register the identity authority handed over, a
laptop or a server, and Docker or PostgreSQL. This page takes that starting point to a
signed, verifiable residency credential, and says plainly what each shortcut costs so the
pilot can be upgraded rather than redone.

Every command here was run as written against a real PostgreSQL and the real application
before it was published, with `NODE_ENV=production`, so the guards that refuse unsafe
defaults were on.

## What has to exist before the SDK is useful

`@openresidency/sdk` is a client. It needs an instance to talk to, and an instance needs:

| Need | What you use when you have nothing else | What it costs |
| --- | --- | --- |
| A database | PostgreSQL 16 from `docker compose up -d db` | nothing |
| A source of identity truth | `DATASET_FILE`: the authority's extract as CSV, JSON or YAML | a file match proves a record exists, not that the applicant owns it; assurance is capped at `basic` and an operator binds the applicant at the desk |
| An issuer signing key | `npm run keys:issuer`, held in an environment variable (`env` backend) | the key lives inside the process; acceptable while the host is sealed, and the first thing to move to an HSM or KMS |
| An operator credential to issue with | the shared `ADMIN_API_KEY` from `.env` | every privileged action audits to one anonymous key; real operations need per-operator keys |
| Three secrets | `SUBJECT_PEPPER`, `OIDC_COOKIE_SECRET`, `ADMIN_API_KEY` | none; generate them once and keep the pepper forever, because rotating it invalidates every stored reference |

Nothing else. No KMS account, no API contract with the identity authority, no wallet app.

## 1. Get the application running

```bash
git clone https://github.com/Harmonizedx/open-residency.git && cd open-residency
npm install
cp .env.example .env
docker compose up -d db
```

Open `.env` and replace the three `change-me` secrets with real random values:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Run that three times, for `SUBJECT_PEPPER`, `OIDC_COOKIE_SECRET` and `ADMIN_API_KEY`. The
pepper is what makes every stored reference non-reversible; write it down somewhere
durable, because a lost pepper means a register nobody can match against.

## 2. Make an issuer key

```bash
npm run keys:issuer
```

It prints four lines. Paste the first three into `.env`:

```
ISSUER_PRIVATE_JWK={"crv":"Ed25519","d":"...","x":"...","kty":"OKP","kid":"issuer-key-1"}
ISSUER_KID=issuer-key-1
ISSUER_KEY_BACKEND=env
```

The fourth line is the public key, which is what verifiers trust and what the DID document
publishes; it is safe to share. The private line is a secret from the moment it appears. In
production it goes in the deployment's secret store, never in a file that is committed, and
the application will warn at every start that the key is resident in the process. That
warning is the reminder to move to a backend where the key cannot be read out; the
deployment guide's production checklist lists them and how far each has been verified.

Without this step the application refuses to start under `NODE_ENV=production`, by design: an
ephemeral key would sign credentials that no verifier trusts and that break on restart.

## 3. Point the register at the extract

The repository ships a worked configuration for exactly this case,
`config/countries/xf-import.yaml`, and a sample extract, `config/datasets/example-registry.csv`:

```
national_id,first_name,last_name,dob,sex,residence_state,origin_state,phone
23456789012,Amina,Bello,1991-03-14,F,Katsina,Kano,+2348030000001
```

Copy both, rename the country, and edit the mapping to your columns:

```bash
mkdir -p config/countries config/datasets
cp config/countries/xf-import.yaml config/countries/ng.yaml   # your jurisdiction
cp /path/to/the-authority-extract.csv config/datasets/register.csv
```

In the YAML, the parts that matter:

- `foundational.dataset.path` and `format`: where the extract is and whether it is CSV, JSON
  or YAML.
- `keyField` and `identifierKey`: which column is the national identifier and what the desk
  will call it in the request.
- `matchFields`: a demographic cross-check, such as surname, so a number alone does not match.
- `responseMapping`: which columns hold the name, date of birth and the residence field. Keep
  residence and origin separate; origin is never evidence of residence.
- `assuranceOnSuccess: basic` and `residency.minAssurance: basic`: what a file match can
  honestly establish. Declaring more resolves to nothing rather than borrowing a stronger
  profile.
- `applicantBinding.required: true` with `attended_comparison`: the operator at the desk
  compares the person to the record. This is what turns "a record exists" into "this person
  is that record", and it is why issuance below carries a `binding`.
- `credential.issuerDid` and `issuerName`: your authority's DID and name. `did:web:` plus the
  host the instance will be served from.
- `subnationalUnits`: the units residents can be registered in.

The application loads every YAML file in the config directory, so remove or move aside the
examples you are not running.

## 4. Start it and check it is ready

```bash
npm run prisma:migrate
npm run start:dev
curl -s localhost:3000/health/ready
```

```json
{"status":"ok","checks":{"database":"ok"}}
```

## 5. Issue the first credential

The desk has verified the person against the record in front of them, so the request carries
that binding:

```bash
curl -s localhost:3000/residency/issue \
  -H 'content-type: application/json' -H "x-admin-key: $ADMIN_API_KEY" \
  -d '{
    "countryCode": "XF", "subnationalUnit": "KT",
    "identifiers": { "nin": "23456789012", "lastName": "Bello" },
    "binding": { "method": "attended_comparison", "ref": "desk:KT-01:operator-7" }
  }'
```

```json
{ "status": "issued", "residentId": "KT-R7M7-F0RV-N", "credentialJwt": "eyJ..." }
```

The same call through the SDK:

```ts
import { OpenResidencyClient } from '@openresidency/sdk';
const jurisdiction = new OpenResidencyClient({ baseUrl: 'http://localhost:3000', adminKey: process.env.ADMIN_API_KEY });
const issued = await jurisdiction.issueResidency({
  countryCode: 'XF', subnationalUnit: 'KT',
  identifiers: { nin: '23456789012', lastName: 'Bello' },
  binding: { method: 'attended_comparison', ref: 'desk:KT-01:operator-7' },
});
```

A wrong surname is refused, not errored, and the applicant gets a reference to contest it
with:

```json
{ "status": "rejected", "reason": "FOUNDATIONAL_FIELD_MISMATCH", "reference": "..." }
```

## 6. Verify it, as a clinic or a school would

No credential of the verifier's own is needed:

```bash
curl -s localhost:3000/residency/verify -H 'content-type: application/json' \
  -d '{ "credential": "<the credentialJwt>" }'
```

```json
{ "valid": true, "subject": { "residentId": "KT-R7M7-F0RV-N", "subnationalUnit": "KT", "foundationalAssurance": "basic", "applicantBinding": "attended_comparison" } }
```

The credential says what it rests on: a `basic` foundational match and an attended binding.
A service deciding what to grant on it can see exactly that.

## What you have, and what you do not

You have a jurisdiction issuing signed W3C credentials from its own register, verifiable
offline by anyone holding the public key, with refusals recorded and appealable, and an
audit chain behind every action. Residents can hold the credential as a QR code or in a
wallet, and sector services can check it with one call.

You do not yet have: a live link to the identity authority (so a record changed or revoked
upstream is not seen until the next extract); a key that cannot be copied out of the host;
named operators (every action currently audits to the shared key); or the SSO layer wired
to any relying party. Each is a configuration step on the same instance, in this order of
value: per-operator keys (`POST /operator/keys`), then the key backend, then the live
provider when the authority offers one. Nothing issued in the meantime has to be re-issued
for the first two; moving the identity source changes what future enrolments can claim, not
what existing credentials say.

## Where this goes next

- Operating it: [`DEPLOY.md`](DEPLOY.md), including the production checklist.
- Letting services sign residents in: [`INTEGRATION.md`](INTEGRATION.md).
- Every route: [`API.md`](API.md); every rule a jurisdiction sets: the README.
