import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
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
  ],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
