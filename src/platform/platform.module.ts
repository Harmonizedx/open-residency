import { Global, Module, OnModuleInit } from '@nestjs/common';
import {
  PrismaAuditStore,
  PrismaConsentStore,
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
    PlatformService,
  ],
  exports: [
    PrismaService,
    PrismaResidencyStore,
    PrismaAuditStore,
    PrismaConsentStore,
    PlatformService,
  ],
})
export class PlatformModule implements OnModuleInit {
  constructor(private platform: PlatformService) {}
  async onModuleInit() {
    await this.platform.init();
  }
}
