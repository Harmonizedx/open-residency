import { Module } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { buildOidcConfiguration } from './oidc.provider';
import { InteractionController } from './interaction.controller';
import { WebAuthnController } from './webauthn.controller';

export const OIDC_PROVIDER = 'OIDC_PROVIDER';

@Module({
  controllers: [InteractionController, WebAuthnController],
  providers: [
    {
      provide: OIDC_PROVIDER,
      inject: [PlatformService],
      useFactory: async (platform: PlatformService) => {
        // oidc-provider is ESM-only. Under TypeScript 7 the module resolution modes that
        // remain (node16/nodenext) refuse a static default import of it from this CommonJS
        // file, so it is loaded dynamically -- which this factory can do for free, being
        // async already. Node has required it successfully all along; the import below just
        // states that relationship in a form the compiler will accept.
        const { default: Provider } = await import('oidc-provider');

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
