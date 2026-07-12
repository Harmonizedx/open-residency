# Contributing to OpenResidency

Thanks for helping build open residency infrastructure. This project is stewarded by
HarmonizedX Limited and released under Apache-2.0.

## Ground rules

- By submitting a contribution, you agree it is licensed under Apache-2.0
  (inbound-equals-outbound). No separate CLA is required.
- Be respectful. Assume good faith.
- Never commit secrets, real national ID numbers, or personal data, including in tests
  or fixtures. Use the MOCK provider and synthetic values.

## Development setup

```bash
npm install
npm run smoke        # runs the framework-agnostic core checks (no DB needed)
npm run prisma:generate
npx tsc --noEmit -p tsconfig.json   # full typecheck
```

To run the server you also need Postgres:

```bash
cp .env.example .env
docker compose up -d db
npm run prisma:migrate
npm run start:dev
```

## What to work on

- New foundational adapters (or config-only country files under `config/countries`).
- Hardening the items listed as caveats in `README.md` (real SSO factor, KMS signing).
- Additional language SDKs generated from `docs/openapi.yaml`.
- Documentation and deployment recipes.

## Pull requests

- Keep changes focused. One concern per PR.
- Add or update a check in `scripts/smoke.ts` when you change core logic.
- Run the full typecheck and the smoke test before pushing.
- Update `docs/openapi.yaml` when you change the HTTP surface, and the SDK to match.
- Describe privacy or security implications explicitly in the PR.

## Reporting bugs

Open an issue with steps to reproduce. For security issues, do not open a public
issue; follow `SECURITY.md`.
