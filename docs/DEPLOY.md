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
