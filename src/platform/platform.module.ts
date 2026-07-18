import { Global, Module, OnModuleInit } from '@nestjs/common';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOtpStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
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
    PrismaOid4vciStore,
    PrismaOid4vpStore,
    PrismaOtpStore,
    PrismaOperatorStore,
    PlatformService,
  ],
  exports: [
    PrismaService,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaConsentStore,
    PrismaOid4vciStore,
    PrismaOid4vpStore,
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
