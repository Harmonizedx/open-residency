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

The image runs `prisma migrate deploy` then starts the server.

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

## Production checklist

- Strong `SUBJECT_PEPPER`, `OIDC_COOKIE_SECRET`, `ADMIN_API_KEY`.
- A `<CLIENT_ID>_CLIENT_SECRET` for every relying party in your country configs, and
  `USSD_GATEWAY_SECRET` if you expose the USSD webhook. The app refuses to start
  without the RP secrets and the cookie key, so a missing one fails the deploy rather
  than silently running on a guessable placeholder.
- `ISSUER_PRIVATE_JWK` from a KMS/HSM, not the ephemeral dev key.
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
