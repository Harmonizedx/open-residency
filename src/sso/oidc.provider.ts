import type { Configuration, ClientMetadata } from 'oidc-provider';
import { exportJWK } from 'jose';
import { PlatformService } from '../platform/platform.service';

/**
 * OpenID Connect configuration that turns the residency system into an Identity
 * Provider. This is the "Sign in with <State>" capability: sector services (Health,
 * Tax, Permits, Subsidy) are OAuth2/OIDC relying parties that never see the citizen's
 * national ID, only the residency claims the citizen consents to release.
 *
 * Authorization across sectors is expressed as scopes. A relying party may only ask
 * for the residency assertion its sector is entitled to; the citizen consents per
 * client, and the resulting ID token / userinfo carries just those claims.
 */

const SECTOR_SCOPES = ['health', 'tax', 'permits', 'subsidy'];

function sectorClients(): ClientMetadata[] {
  const base = process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000';
  const rp = (id: string, port: number, scopes: string): ClientMetadata => ({
    client_id: id,
    client_secret: process.env[`${id.toUpperCase()}_CLIENT_SECRET`] ?? `${id}-dev-secret`,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      process.env[`${id.toUpperCase()}_REDIRECT_URI`] ?? `http://localhost:${port}/callback`,
    ],
    post_logout_redirect_uris: [`http://localhost:${port}`],
    scope: scopes,
    token_endpoint_auth_method: 'client_secret_basic',
  });

  // Each sector RP gets openid + profile + residency + its own sector scope.
  return [
    rp('health', 4001, 'openid profile residency health'),
    rp('tax', 4002, 'openid profile residency tax'),
    rp('permits', 4003, 'openid profile residency permits'),
    rp('subsidy', 4004, 'openid profile residency subsidy'),
  ].map((c) => ({ ...c, [`_note`]: base } as ClientMetadata));
}

export async function buildOidcConfiguration(
  platform: PlatformService,
): Promise<Configuration> {
  const privateJwk = await exportJWK(platform.getIssuerKey().privateKey);
  privateJwk.kid = platform.getIssuerKey().kid;
  privateJwk.alg = 'EdDSA';
  privateJwk.use = 'sig';

  return {
    clients: sectorClients(),

    jwks: { keys: [privateJwk as any] },

    scopes: ['openid', 'offline_access', ...SECTOR_SCOPES, 'residency'],

    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name', 'birthdate', 'gender'],
      residency: [
        'resident_id',
        'country_code',
        'subnational_unit',
        'assurance_level',
        'provisional',
      ],
    },

    /**
     * Resolve a resident (by residentId as the OIDC subject) to claims, sourced from
     * the residency store. Sector scopes gate which RP may request the residency
     * assertion but do not add PII beyond the residency claim set.
     */
    async findAccount(_ctx, id) {
      const record = await platform.getStore().findByResidentId(id);
      if (!record) return undefined;
      return {
        accountId: id,
        async claims() {
          return {
            sub: id,
            name: record.person.fullName,
            given_name: record.person.givenName,
            family_name: record.person.familyName,
            birthdate: record.person.dateOfBirth,
            gender: record.person.gender,
            resident_id: record.residentId,
            country_code: record.countryCode,
            subnational_unit: record.subnationalUnit,
            assurance_level: record.assuranceLevel,
            provisional: record.provisional,
          };
        },
      };
    },

    interactions: {
      url(_ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },

    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      introspection: { enabled: true },
      resourceIndicators: { enabled: false },
    },

    pkce: { required: () => true },

    cookies: {
      keys: [process.env.OIDC_COOKIE_SECRET ?? 'dev-cookie-secret-change-me'],
    },

    ttl: {
      AccessToken: 3600,
      AuthorizationCode: 600,
      IdToken: 3600,
      RefreshToken: 14 * 24 * 3600,
      Interaction: 3600,
      Session: 14 * 24 * 3600,
      Grant: 14 * 24 * 3600,
    },
  };
}
