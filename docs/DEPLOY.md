# Deployment

## Local (Docker Compose)

```bash
cp .env.example .env
docker compose up -d db
npm install
npm run prisma:migrate
npm run start:dev
```

App on `http://localhost:3000`. Reference UI at `/app/index.html`, docs at `/docs`.

## Container image

```bash
docker build -t openresidency:local .
docker compose up --build
```

The image's own entrypoint is the server alone (`node dist/main.js`). **Who runs the
migration depends on the deploy path**, and the difference is not cosmetic:

| Path | How migrations run |
| --- | --- |
| Kubernetes / Helm | An **init container**, from the same image, before the server starts |
| Docker Compose | The container's `command` migrates, then serves — compose has no init containers |

Both invoke the Prisma CLI directly (`./node_modules/.bin/prisma migrate deploy`) rather
than through `npx`, because the runtime image ships no package manager.

The init container is the right shape wherever replicas exist: several of them racing to
migrate one database is a failure mode you only see under load, and separating the steps
lets a migration be rolled back as a deploy decision. Compose is exempt because it runs a
single container — the race it protects against cannot occur.

The image carries no package manager. npm vendors its own dependency tree, which nothing
in the application can prune and which keeps appearing in image scans; it was only present
to run `npx`, and the Prisma CLI has a direct entry point that does not need it. A runtime
image that cannot install packages is also one less capability for a compromised process
to reach for.

That separation is deliberate. A server that migrates on boot has every replica racing to
migrate the same database, and a rollback has to be a schema decision rather than a deploy
one. It does mean the image carries the Prisma CLI, which is why `prisma` is a dependency
rather than a devDependency — a runtime artifact that cannot work without a package has a
runtime dependency on it, whatever the manifest used to say.

## Kubernetes (raw manifests)

```bash
kubectl apply -f deploy/k8s/postgres.yaml   # optional: in-cluster DB for evaluation
kubectl apply -f deploy/k8s/app.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

Edit the ConfigMap and Secret first. For production, source secrets from a sealed
secret, external-secrets operator, or cloud KMS, and use a managed Postgres.

## Kubernetes (Helm)

```bash
helm install openres deploy/helm/openresidency \
  --namespace openresidency --create-namespace \
  --set image.repository=ghcr.io/your-org/openresidency \
  --set image.tag=1.0.0 \
  --set-string secrets.subjectPepper="$(openssl rand -hex 32)" \
  --set-string secrets.adminApiKey="$(openssl rand -hex 24)" \
  --set ingress.host=id.yourstate.gov
```

To reference an existing secret instead of chart-managed values, set
`secrets.existingSecret=<name>`.

## The gateway / edge

`deploy/k8s/ingress.yaml` is the API gateway edge: TLS termination, per-IP rate
limits, request size caps, and tighter limits on `/admin` and `/audit`. The app also
rate-limits every route and enforces the admin key, so it is safe if reached directly.
Swap the ingress for Kong / APISIX / a cloud gateway without changing the app.

## Deployment-wide profiles come from the FIRST country config

`operatorAuth`, `messaging`, `contactDirectory`, `presentation` and `oidc.subjectType`
are deployment-wide, and are read from the first config loaded — files are loaded in
sorted filename order. If you run several countries from one deployment, put these blocks
in the config that sorts first, or the mode you get will not be the mode you wrote.

## Operating

What the service gives a monitoring stack, and what to do with it.

### Health

| Endpoint | Answers | Use as |
| --- | --- | --- |
| `GET /health/live` | 200 when the process answers HTTP | liveness probe |
| `GET /health/ready` | 200 when the database answers within 2 s; 503 with `{ "checks": { "database": "failed" } }` otherwise | readiness probe |

Both are unauthenticated and exempt from the application rate limit. The manifests in
`deploy/` already probe them. A failure body names the check, never the error — a connection
string inside an exception is not something to return to whoever can reach the port.

### The operations log

JSON, one object per line, to stdout; collect it with whatever ships container logs. Level
from `LOG_LEVEL` (`info` by default). Every line carries `level`, `time`, `service`; a request
line carries `reqId`, `method`, `route`, `status`, `durationMs`.

- **`route` is the pattern, not the path** — `/residency/:residentId`, never the id. The URL,
  query string, body and headers are not logged at all. Any object logged elsewhere has
  `identifiers`, `nin`, `sample`, `authorization`, `x-api-key`, one-time codes and tokens
  redacted wherever they appear. `npm run smoke:observability` asserts that an identifier
  submitted to the service reaches neither the log nor a metric label.
- **`reqId`** is the `x-request-id` on the response. A well-formed inbound value (as an
  ingress sets) is honoured, so one id follows a request from the edge in; anything else is
  replaced. Ask for it when a registrar reports a problem.
- Probe traffic is logged at `debug`; a 5xx is logged at `error`.

**This is not the audit log.** The audit chain (`/audit`, `src/core/audit/`) is a
tamper-evident record of what happened to which residency, kept for the auditor and retained
under its own rules. The operations log is for whoever is on call, retained for days, and may
be discarded. Ship them to different places; do not reach for the audit chain during an
incident because the operations log was not there.

### Metrics

Prometheus exposition on `METRICS_PORT` — a **separate listener**, not the application port,
so the ingress never routes to it. Unset, nothing listens. The Helm chart's `metrics.enabled`
adds the container port and a `prometheus.io/scrape` pod annotation; the metrics port is
deliberately absent from the Service.

| Series | What it answers |
| --- | --- |
| `openresidency_http_request_duration_seconds` (histogram; `method`, `route`, `status`) | Is the service taking requests, and how slowly |
| `openresidency_issuance_total` (`status`, `reason`, `unit`) | Are enrolments being issued or refused, for what class of reason, in which declared unit |
| `openresidency_foundational_verification_total` / `_duration_seconds` (`provider`, `outcome`) | Is the national ID source answering, and how fast |
| `openresidency_background_job_last_success_timestamp_seconds` (`job`) | Are audit checkpoints, peer status syncs and OIDC sweeps still running |
| `process_*`, `nodejs_*` | The runtime |

Every label value is drawn from a bounded set: route patterns, declared unit codes (or
`undeclared`), reason *classes*, provider codes. Nothing about a person is a label.

**Alert on**, at minimum:

- readiness flapping — `kube_pod_status_ready` for the deployment, or the `/health/ready`
  5xx rate in the ingress;
- `rate(openresidency_http_request_duration_seconds_count{status=~"5.."}[5m]) > 0` on
  `/residency/issue` and `/identity/verify` — the desks are failing;
- `rate(openresidency_foundational_verification_total{outcome="error"}[10m])` rising — the
  national ID gateway is down or refusing, which presents to a registrar as "slow";
- `time() - openresidency_background_job_last_success_timestamp_seconds{job="audit_checkpoint"}`
  exceeding several times `AUDIT_CHECKPOINT_SECONDS` — the audit tail is unanchored;
- the same for `federation_status_refresh` against `FEDERATION_STATUS_REFRESH_SECONDS`, where
  peers are configured — a peer's revocations are going unnoticed.

### Not provided

Distributed tracing. There is one process and a database; the request id covers correlation.
Revisit when a second service exists.

## Production checklist

- Strong `SUBJECT_PEPPER`, `OIDC_COOKIE_SECRET`, `ADMIN_API_KEY`.
- A `<CLIENT_ID>_CLIENT_SECRET` for every relying party in your country configs, and
  `USSD_GATEWAY_SECRET` if you expose the USSD webhook. The app refuses to start
  without the RP secrets and the cookie key, so a missing one fails the deploy rather
  than silently running on a guessable placeholder.
- An issuer signing key with real custody, where compromising the application does not
  compromise the key. **How far each backend has actually been verified differs — the
  "verified" column is the part to read before you rely on one:**

  | Backend | Configure with | Verified how far |
  | --- | --- | --- |
  | `pkcs11` | `PKCS11_LIBRARY`, `PKCS11_PIN`, `PKCS11_KEY_LABEL` | **Tested** end to end against SoftHSM (`npm run smoke:hsm`), including that the key cannot be extracted |
  | `gcpkms` | `GCP_KMS_KEY_NAME` | Protocol + issuance tested against a **mock** (`npm run smoke:gcpkms`); real IAM/endpoints unverified |
  | `awskms` | `AWS_KMS_KEY_ID`, `AWS_KMS_REGION` | Protocol + issuance tested against a **mock** (`npm run smoke:awskms`); real IAM/endpoints unverified |
  | `env` | `ISSUER_PRIVATE_JWK` | Tested, but the key is resident in this process — acceptable only if the environment is sealed |

  Per-backend setup notes:
  - **Google Cloud KMS** — create the key with algorithm `EC_SIGN_ED25519` and protection level
    `HSM`; grant the service account `roles/cloudkms.signer` and `roles/cloudkms.viewer`.
  - **AWS KMS** — create the key with key spec `ECC_NIST_EDWARDS25519` and usage `SIGN_VERIFY`;
    the caller needs `kms:Sign` and `kms:GetPublicKey`. Credentials resolve from env vars, IRSA,
    an ECS task role, then an EC2 instance profile.
  - **AWS CloudHSM** — use `pkcs11` with the CloudHSM PKCS#11 library.
  - **Azure** — use `pkcs11` with Azure Dedicated HSM or Luna Cloud HSM (Thales Luna 7, which
    ships a PKCS#11 library). *Untested here:* the interface matches, but nobody has run this
    against a real Luna appliance, so treat it as unproven until you have.
  - **Azure Key Vault and Managed HSM cannot be used at all.** They offer no Ed25519 curve (only
    P-256/P-256K/P-384/P-521 with ES256/384/512), and their Sign operation is documented as
    "sign hash" — the caller supplies a digest. PureEdDSA signs the message and derives its
    nonce from it, so it cannot accept a pre-hash. AWS and GCP each had to expose an explicit
    raw-message mode to support Ed25519; Azure Key Vault has no equivalent.

  The app refuses to start in production with no key configured rather than minting an
  ephemeral one. **Whichever backend you pick, sign one credential against the real key and
  verify it before opening enrollment** — the test suites cover the protocol, not your IAM,
  your key policy, or your hardware.
- `OIDC_SIGNING_JWK` if SSO is enabled and the issuer key is in an HSM — `oidc-provider` signs
  id_tokens itself and cannot use a remote signer, so it needs its own key.
- `ISSUER_RETIRED_JWKS` after any key rotation, carrying the public halves of previous keys.
  Credentials already issued stay valid for years; omitting the retired key makes every one of
  them fail verification as an untrusted issuer.
- `operatorAuth.mode: oidc`, pointed at the ministry's staff directory. The `sharedKey`
  default carries no operator identity (every action audits to the same actor), no roles
  and no rotation; it warns on every boot. `local` is a full alternative (scrypt, TOTP,
  lockout, rotatable per-operator keys) for deployments with no IdP, but it makes this
  system a staff credential store.
- A `messaging` block naming a real aggregator, plus a `contactDirectory`. Without them
  the one-time-code sign-in fallback is off. `provider: LOG` writes live codes to the
  service log and now refuses to start unless explicitly acknowledged.
- `CONTACT_ENCRYPTION_KEY` if `contactDirectory.mode: encrypted` (`openssl rand -hex 32`).
  Prefer `external` where a contact service already exists — then no recoverable phone
  number is stored here at all.
- `USSD_GATEWAY_SECRET` if the USSD webhook is exposed.
- The foundational provider secret named by each config's `foundational.auth.secretEnv`
  (e.g. `NIN_GATEWAY_KEY`). A missing one now fails at the point of use instead of
  sending an empty header and surfacing the gateway's 401 as an unexplained error.
- A real SSO authentication factor in `src/sso/interaction.controller.ts`.
- Confirmed national ID API contract and legal basis with each identity authority.
- A data protection impact assessment and records of processing.
- Backups and monitoring for Postgres; log shipping for the audit trail.
- A scraper pointed at `METRICS_PORT` and the alerts under [Operating](#operating), so an
  outage is noticed by a pager rather than by a registrar.
