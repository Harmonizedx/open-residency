// SPDX-License-Identifier: Apache-2.0
import type { Configuration, ClientMetadata } from 'oidc-provider' with { 'resolution-mode': 'import' };
import { PlatformService } from '../platform/platform.service';
import { RelyingPartyConfig } from '../core/config/country-config';
import { pairwiseSubject } from '../core/sso/pairwise';
import { createOidcAdapterFactory } from '../core/sso/oidc-store';

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

/**
 * Read a required secret from the environment, or refuse to boot.
 *
 * These used to fall back to a placeholder derived from public data so local development
 * worked with no .env at all. That silently produced guessable credentials: a deployment
 * that forgot one env var got a working, wrong-secret provider and no signal anywhere
 * that it had. Unlike the issuer key and subject pepper -- which warn loudly but can
 * degrade to a usable dev mode -- there is no safe degraded mode for a client secret or
 * a cookie key, so this fails closed. `.env.example` carries dev values, and the
 * documented `cp .env.example .env` path still works out of the box.
 */
function requireSecret(name: string, purpose: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set. ${purpose} Refusing to start rather than fall back to a ` +
        `guessable placeholder. Copy .env.example to .env for local development.`,
    );
  }
  return value;
}

/** Translate one config-declared relying party into oidc-provider client metadata. */
function toClientMetadata(rp: RelyingPartyConfig, subjectType: 'pairwise' | 'public'): ClientMetadata {
  return {
    client_id: rp.clientId,
    subject_type: subjectType,
    // The secret lives in the environment, never in config or git.
    client_secret: requireSecret(
      `${rp.clientId.toUpperCase()}_CLIENT_SECRET`,
      `It is the client secret for relying party "${rp.clientId}", which authenticates ` +
        `that service at the token endpoint.`,
    ),
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: rp.redirectUris,
    post_logout_redirect_uris: rp.postLogoutRedirectUris,
    // The deployment signs with a single Ed25519 key (see PlatformService.oidcSigningJwk),
    // so id_tokens are EdDSA. oidc-provider defaults a client's id_token_signed_response_alg
    // to RS256, and with no RS256 key in the JWKS it then rejects the client as
    // `invalid_client_metadata` at the authorization endpoint -- i.e. every sign-in fails.
    // Pin the alg to the one we actually sign with. `smoke:sso-oidc` is the test that
    // catches this: it only shows up once the provider is booted and a real flow is driven.
    id_token_signed_response_alg: 'EdDSA',
    // `openid` plus this RP's sector, plus only those broader scopes it was explicitly
    // granted. `residency` is no longer handed out automatically -- see the note on
    // `scopes` in country-config.ts for why a universally-available resident_id defeats
    // pairwise subjects entirely.
    scope: ['openid', ...rp.scopes, rp.sector].join(' '),
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
  // The SSO layer's own signing key. `oidc-provider` signs internally and takes only
  // literal private JWKs, so this is the one path that cannot use an HSM-held key --
  // see PlatformService.oidcSigningJwk for why that gets its own key rather than
  // pulling the credential key back out of the HSM.
  const privateJwk = await platform.oidcSigningJwk();

  const rps = relyingParties(platform);
  // Subject type is deployment-wide, read from the default config like the other
  // deployment-level profiles.
  const subjectType = platform.listConfigs()[0]?.oidc.subjectType ?? 'pairwise';
  // The set of sector scopes is whatever the configured RPs actually use, so a country
  // can add a sector by editing YAML -- no code change, and no scope registered that
  // nobody requests.
  const sectorScopes = [...new Set(rps.map((rp) => rp.sector))];

  return {
    /**
     * Where the provider keeps sessions, interactions, codes, tokens and grants.
     *
     * Left unset, oidc-provider silently uses a development adapter backed by a Map in
     * process memory. That works in a smoke test, which drives one process, and fails in
     * production the moment `replicaCount` exceeds one: the authorization code is minted on
     * the citizen's redirect and redeemed by the relying party's backend on a separate
     * connection, which balances to whichever replica the ingress picks. The cookie still
     * verifies there -- OIDC_COOKIE_SECRET is shared -- so the citizen gets a silent bounce
     * back to login rather than an error anyone can trace. It also means every restart logs
     * the whole jurisdiction out, which is what the 14-day Session and Grant TTLs below
     * would otherwise be promising.
     */
    adapter: createOidcAdapterFactory(platform.getOidcStore()) as any,

    clients: rps.map((rp) => toClientMetadata(rp, subjectType)),

    jwks: { keys: [privateJwk as any] },

    scopes: ['openid', 'offline_access', 'residency', ...sectorScopes],

    // Pairwise must be explicitly enabled. oidc-provider defaults `subjectTypes` to
    // ['public'] and then rejects any client declaring `subject_type: pairwise` with
    // "subject_type must be 'public'" -- which is every client here, since the default
    // is pairwise. Without this the whole pairwise-subject design below is dead config:
    // clients fail to authorize and nothing falls back. `smoke:sso-oidc` catches it.
    subjectTypes: ['public', 'pairwise'],

    /**
     * Derive a per-relying-party subject identifier.
     *
     * The `sub` used to be the residency id itself, identical at every service. That let
     * any two MDAs that could compare records -- lawfully or not -- join them on a single
     * key and assemble a cross-government profile of a citizen, which is precisely the
     * thing a federated identity layer is supposed to make hard.
     *
     * The derivation is HMAC(pepper, clientId + residentId), reusing the same
     * SUBJECT_PEPPER that makes foundational subject references non-reversible. Two
     * properties matter: it is deterministic, so a service keeps recognising its own
     * returning users across sessions and restarts; and it is one-way and unguessable
     * without the pepper, so a service cannot invert its own identifiers back to a
     * residency id, nor recompute what another service would see.
     */
    pairwiseIdentifier(_ctx, accountId, client) {
      return pairwiseSubject(platform.getSubjectPepper(), client.clientId, accountId);
    },

    claims: {
      // acr/amr/auth_time are authentication-event claims: they describe HOW and WHEN the
      // citizen signed in, which is what lets a relying party enforce assurance step-up.
      // oidc-provider only emits a claim that belongs to a granted scope, and these are set
      // on the session by the interaction (see InteractionController.finishLogin), so they
      // are attached to `openid` -- always granted -- rather than gated behind an
      // acr_values request the RP might not make.
      openid: ['sub', 'acr', 'amr', 'auth_time'],
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
     *
     * CLAIM RELEASE IS GATED ON THE CONSENT RECORD (ORCS §9). Consent status, expiry and the
     * legal basis were all recorded and then read nowhere on this path: a withdrawn consent, a
     * lapsed one, or one whose lawful basis had been repealed went on releasing the full claim
     * set for the life of the tokens, because `claims()` only ever consulted the residency
     * store. §9 requires expiry to "prevent further processing automatically", and a rule
     * enforced nowhere is not a rule.
     *
     * Refusal degrades to `sub` alone rather than failing the request. `sub` is the pairwise
     * subject identifier the relying party already holds, so returning it discloses nothing
     * further, and authentication keeps working while the personal data stops flowing --
     * which is the distinction between withdrawing consent and being locked out of the login.
     *
     * Already-issued ID tokens cannot be recalled; this takes effect on every userinfo read and
     * every subsequent token. Immediate revocation of the session is what `POST /consent/:id/revoke`
     * does in addition, by destroying the grant.
     */
    async findAccount(ctx, id) {
      const record = await platform.getStore().findByResidentId(id);
      if (!record) return undefined;
      const clientId = (ctx as any)?.oidc?.client?.clientId as string | undefined;
      return {
        accountId: id,
        async claims() {
          const minimal = { sub: id };
          // No client in context means this is not a claim release to a relying party (the
          // interaction itself resolves the account before a client is bound). Nothing is
          // disclosed here, so there is nothing to gate.
          if (!clientId) return minimal;

          const consent = platform.getConsent();
          const governing = await consent.governing(id, clientId);
          if (!governing) return minimal;
          const decision = consent.mayProcess(governing);
          if (!decision.permitted) return minimal;

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
      keys: [
        requireSecret(
          'OIDC_COOKIE_SECRET',
          'It signs OIDC session cookies; a known key lets anyone forge a session.',
        ),
      ],
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
