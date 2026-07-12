import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { urlencoded, json } from 'express';
import { join } from 'node:path';
import type Provider from 'oidc-provider';
import { AppModule } from './app.module';
import { OIDC_PROVIDER } from './sso/oidc.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });

  // Body parsing: JSON for the residency API, urlencoded for the OIDC interaction forms.
  app.use(json());
  app.use(urlencoded({ extended: false }));

  // Reference UI (static). Served under /app so it never collides with API routes.
  app.useStaticAssets(join(process.cwd(), 'public'), { prefix: '/app' });

  // Mount the OpenID Connect provider at /oidc so its issuer is <base>/oidc.
  const provider = app.get<Provider>(OIDC_PROVIDER);
  app.use('/oidc', provider.callback());

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  // eslint-disable-next-line no-console
  console.log(`OpenResidency listening on :${port}`);
  console.log(`  Reference UI       : GET  /app/index.html`);
  console.log(`  API docs (Swagger) : GET  /docs`);
  console.log(`  OpenAPI spec       : GET  /openapi.yaml`);
  console.log(`  Residency API      : POST /residency/issue`);
  console.log(`  Identity API       : POST /identity/verify`);
  console.log(`  OIDC discovery     : GET  /oidc/.well-known/openid-configuration`);
  console.log(`  Issuer DID document: GET  /.well-known/did.json`);
}

bootstrap();
