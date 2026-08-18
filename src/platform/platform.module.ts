// SPDX-License-Identifier: Apache-2.0
import { Global, Module, OnModuleInit } from '@nestjs/common';
import {
  PrismaAuditStore,
  PrismaAuditCheckpointStore,
  PrismaConsentStore,
  PrismaLegalBasisStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOidcStore,
  PrismaRefusalStore,
  PrismaOtpStore,
    PrismaUpstreamAuthStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
  PrismaWebAuthnChallengeStore,
  PrismaWebAuthnCredentialStore,
  PrismaService,
} from '../prisma/prisma.service';
import { KeyCustody } from './key-custody';
import { OperatorIdentity } from './operator-identity';
import { PlatformService } from './platform.service';

@Global()
@Module({
  providers: [
    PrismaService,
    KeyCustody,
    OperatorIdentity,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaAuditCheckpointStore,
    PrismaConsentStore,
    PrismaLegalBasisStore,
    PrismaOid4vciStore,
    PrismaOid4vpStore,
    PrismaOidcStore,
  PrismaRefusalStore,
    PrismaOtpStore,
    PrismaUpstreamAuthStore,
    PrismaOperatorStore,
    PrismaWebAuthnChallengeStore,
    PrismaWebAuthnCredentialStore,
    PlatformService,
  ],
  exports: [
    PrismaService,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaAuditCheckpointStore,
    PrismaConsentStore,
    PrismaLegalBasisStore,
    PrismaOid4vciStore,
    PrismaOid4vpStore,
    PrismaOidcStore,
  PrismaRefusalStore,
    PrismaOtpStore,
    PrismaUpstreamAuthStore,
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
