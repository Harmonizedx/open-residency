// SPDX-License-Identifier: Apache-2.0
import { Module, ValidationPipe } from '@nestjs/common';
import { APP_GUARD, APP_PIPE } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { PlatformModule } from './platform/platform.module';
import { ResidencyModule } from './residency/residency.module';
import { IdentityModule } from './identity/identity.module';
import { ConsentModule } from './consent/consent.module';
import { AuditModule } from './audit/audit.module';
import { AdminModule } from './admin/admin.module';
import { OfflineModule } from './offline/offline.module';
import { SsoModule } from './sso/oidc.module';
import { Oid4vciModule } from './oid4vci/oid4vci.module';
import { Oid4vpModule } from './oid4vp/oid4vp.module';
import { VcApiModule } from './vcapi/vcapi.module';
import { MetaModule } from './meta/meta.module';
import { OperatorModule } from './operator/operator.module';
import { AssuranceModule } from './assurance/assurance.module';

@Module({
  imports: [
    // In-app rate limiting: the application half of the gateway posture. Coarse edge
    // limits live in the Ingress (deploy/k8s); this protects every route regardless.
    ThrottlerModule.forRoot([
      { name: 'default', ttl: 60_000, limit: Number(process.env.RATE_LIMIT_PER_MINUTE ?? 120) },
    ]),
    PlatformModule,
    ResidencyModule,
    IdentityModule,
    ConsentModule,
    AuditModule,
    AdminModule,
    OfflineModule,
    SsoModule,
    Oid4vciModule,
    Oid4vpModule,
    VcApiModule,
    MetaModule,
    OperatorModule,
    AssuranceModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    // Global request validation. Registered as an APP_PIPE provider rather than a main.ts
    // `useGlobalPipes` call so it is active wherever AppModule is instantiated -- the server,
    // the full-stack e2e harness, and any future test -- and cannot silently be absent in one
    // bootstrap path. `whitelist` strips unknown props, `forbidNonWhitelisted` rejects them,
    // `transform` instantiates DTOs (and coerces query types). Only endpoints whose param is a
    // decorated DTO class are validated; protocol endpoints typed as `Record<...>` (OAuth /
    // OID4VCI / VC-API) are skipped, preserving wallet and conformance interop.
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    },
  ],
})
export class AppModule {}
