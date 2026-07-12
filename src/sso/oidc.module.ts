import { Module } from '@nestjs/common';
import Provider from 'oidc-provider';
import { PlatformService } from '../platform/platform.service';
import { buildOidcConfiguration } from './oidc.provider';
import { InteractionController } from './interaction.controller';

export const OIDC_PROVIDER = 'OIDC_PROVIDER';

@Module({
  controllers: [InteractionController],
  providers: [
    {
      provide: OIDC_PROVIDER,
      inject: [PlatformService],
      useFactory: async (platform: PlatformService) => {
        // Ensure the core (issuer key etc.) is initialized before building the provider.
        if (!platform.getIssuerKey?.()) await platform.init();
        const issuer = `${process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000'}/oidc`;
        const config = await buildOidcConfiguration(platform);
        const provider = new Provider(issuer, config);
        provider.proxy = true;
        return provider;
      },
    },
  ],
  exports: [OIDC_PROVIDER],
})
export class SsoModule {}
