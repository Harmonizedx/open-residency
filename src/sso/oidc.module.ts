// SPDX-License-Identifier: Apache-2.0
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

        // Fail closed if the storage adapter ever goes missing again.
        //
        // oidc-provider does not complain when `adapter` is absent -- it falls back to an
        // in-process Map and logs a warning nobody reads in a running deployment. The
        // symptom appears later, as intermittent failed sign-ins on a multi-replica
        // cluster, and looks nothing like its cause. Refusing to boot is the only signal
        // that arrives before citizens are affected. Same reasoning as `requireSecret`
        // in oidc.provider.ts: there is no safe degraded mode here.
        if (!config.adapter) {
          throw new Error(
            'OIDC provider has no storage adapter configured. It would fall back to ' +
              'in-process memory, which loses every session on restart and breaks the ' +
              'authorization-code exchange whenever more than one replica runs. ' +
              'See buildOidcConfiguration in src/sso/oidc.provider.ts.',
          );
        }

        const provider = new Provider(issuer, config);
        provider.proxy = true;
        return provider;
      },
    },
  ],
  exports: [OIDC_PROVIDER],
})
export class SsoModule {}
