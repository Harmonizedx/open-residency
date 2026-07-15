import type { Configuration, ClientMetadata } from 'oidc-provider';
import { exportJWK } from 'jose';
import { PlatformService } from '../platform/platform.service';
import { RelyingPartyConfig } from '../core/config/country-config';

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

/** Translate one config-declared relying party into oidc-provider client metadata. */
function toClientMetadata(rp: RelyingPartyConfig): ClientMetadata {
  return {
    client_id: rp.clientId,
    // The secret lives in the environment, never in config or git. Falls back to a dev
    // placeholder only when the env var is unset, so local development works out of the box.
    client_secret:
      process.env[`${rp.clientId.toUpperCase()}_CLIENT_SECRET`] ?? `${rp.clientId}-dev-secret`,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: rp.redirectUris,
    post_logout_redirect_uris: rp.postLogoutRedirectUris,
    // openid + profile + residency, plus the one sector scope this RP is entitled to.
    scope: `openid profile residency ${rp.sector}`,
    token_endpoint_auth_method: 'client_secret_basic',
  };
}

/** Every relying party across all country configs. */
function relyingParties(platform: PlatformService): RelyingPartyConfig[] {
  return platform.listConfigs().flatMap((c) => c.oidc.relyingParties);
}

export async function buildOidcConfiguration(
  platform: PlatformService,
): Promise<Configuration> {
  const privateJwk = await exportJWK(platform.getIssuerKey().privateKey);
  privateJwk.kid = platform.getIssuerKey().kid;
  privateJwk.alg = 'EdDSA';
  privateJwk.use = 'sig';

  const rps = relyingParties(platform);
  // The set of sector scopes is whatever the configured RPs actually use, so a country
  // can add a sector by editing YAML -- no code change, and no scope registered that
  // nobody requests.
  const sectorScopes = [...new Set(rps.map((rp) => rp.sector))];

  return {
    clients: rps.map(toClientMetadata),

    jwks: { keys: [privateJwk as any] },

    scopes: ['openid', 'offline_access', 'residency', ...sectorScopes],

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
