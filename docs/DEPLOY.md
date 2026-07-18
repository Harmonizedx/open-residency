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

## Production checklist

- Strong `SUBJECT_PEPPER`, `OIDC_COOKIE_SECRET`, `ADMIN_API_KEY`.
- A `<CLIENT_ID>_CLIENT_SECRET` for every relying party in your country configs, and
  `USSD_GATEWAY_SECRET` if you expose the USSD webhook. The app refuses to start
  without the RP secrets and the cookie key, so a missing one fails the deploy rather
  than silently running on a guessable placeholder.
- `ISSUER_PRIVATE_JWK` from a KMS/HSM, not the ephemeral dev key.
- Operator authentication in front of `/admin`, `/audit`, and residency
  issuance/revocation. The built-in admin key is a single shared static secret with no
  per-operator identity, roles, or rotation — every privileged action audits to the same
  actor. Replace it with operator SSO before government staff use the system.
- A real SSO authentication factor in `src/sso/interaction.controller.ts`.
- Confirmed national ID API contract and legal basis with each identity authority.
- A data protection impact assessment and records of processing.
- Backups and monitoring for Postgres; log shipping for the audit trail.
