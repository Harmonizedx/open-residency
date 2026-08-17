// SPDX-License-Identifier: Apache-2.0
import { Global, Module, OnModuleInit } from '@nestjs/common';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaLegalBasisStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOidcStore,
  PrismaRefusalStore,
  PrismaOtpStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
  PrismaWebAuthnChallengeStore,
  PrismaWebAuthnCredentialStore,
  PrismaService,
} from '../prisma/prisma.service';
import { PlatformService } from './platform.service';

@Global()
@Module({
  providers: [
    PrismaService,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaConsentStore,
    PrismaLegalBasisStore,
    PrismaOid4vciStore,
    PrismaOid4vpStore,
    PrismaOidcStore,
  PrismaRefusalStore,
    PrismaOtpStore,
    PrismaOperatorStore,
    PrismaWebAuthnChallengeStore,
    PrismaWebAuthnCredentialStore,
    PlatformService,
  ],
  exports: [
    PrismaService,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaConsentStore,
    PrismaLegalBasisStore,
    PrismaOid4vciStore,
    PrismaOid4vpStore,
    PrismaOidcStore,
  PrismaRefusalStore,
    PrismaOtpStore,
    PrismaOperatorStore,
    PlatformService,
  ],
})
export class PlatformModule implements OnModuleInit {
  constructor(private platform: PlatformService) {}
  async onModuleInit() {
    await this.platform.init();
  }
}
