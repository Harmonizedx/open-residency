// SPDX-License-Identifier: Apache-2.0
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { urlencoded, json } from 'express';
import { join } from 'node:path';
import type Provider from 'oidc-provider' with { 'resolution-mode': 'import' };
import { AppModule } from './app.module';
import { OIDC_PROVIDER } from './sso/oidc.module';
import { createRootLogger } from './observability/logging';
import { PinoNestLogger } from './observability/nest-logger';
import { requestObserver } from './observability/http';
import { metricsPortFromEnv, startMetricsServer } from './observability/metrics';

async function bootstrap() {
  // One logger for the process: Nest's own messages and every `new Logger()` in the app go
  // through it, so the output is one JSON shape a shipper can parse. See observability/logging.
  const log = createRootLogger();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bodyParser: false,
    logger: new PinoNestLogger(log),
  });

  // Request observation goes FIRST, ahead of the body parsers, so a request the parser rejects
  // is still timed, counted, and answered with a request id.
  app.use(requestObserver(log));

  // Body parsing: JSON for the residency API, urlencoded for the OIDC interaction forms.
  app.use(json());
  app.use(urlencoded({ extended: false }));

  // Request validation is a global APP_PIPE in AppModule, so it applies here and in the
  // full-stack e2e harness alike -- see the note there.

  // Reference UI (static). Served under /app so it never collides with API routes.
  app.useStaticAssets(join(process.cwd(), 'public'), { prefix: '/app' });

  // Mount the OpenID Connect provider at /oidc so its issuer is <base>/oidc.
  const provider = app.get<Provider>(OIDC_PROVIDER);
  app.use('/oidc', provider.callback());

  // SIGTERM from the orchestrator runs the module destroy hooks -- background timers stop,
  // the HSM session is released -- instead of the process dying mid-request.
  app.enableShutdownHooks();

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);

  // Metrics on their own port, so the ingress never sees them. Unset means nothing listens.
  const metricsPort = metricsPortFromEnv();
  const metrics = metricsPort === undefined ? undefined : await startMetricsServer(metricsPort, log);
  if (metrics) {
    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      process.once(signal, () => metrics.close());
    }
  }

  log.info(
    {
      port,
      metricsPort: metrics ? (metrics.address() as { port: number }).port : null,
      routes: {
        referenceUi: 'GET  /app/index.html',
        apiDocs: 'GET  /docs',
        openapi: 'GET  /openapi.yaml',
        residency: 'POST /residency/issue',
        identity: 'POST /identity/verify',
        oidcDiscovery: 'GET  /oidc/.well-known/openid-configuration',
        issuerDid: 'GET  /.well-known/did.json',
        health: 'GET  /health/live, /health/ready',
      },
    },
    'OpenResidency listening',
  );
}

bootstrap().catch((err: unknown) => {
  // A boot refusal -- no pepper, no issuer key, a missing relying-party secret -- must be
  // legible in the same log stream as everything else, not a bare stack on stderr.
  createRootLogger().fatal({ err }, 'OpenResidency failed to start');
  process.exit(1);
});
