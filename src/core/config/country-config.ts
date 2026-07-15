import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { load as loadYaml } from 'js-yaml';
import { z } from 'zod';

/**
 * A country configuration is the single source of truth for onboarding a new
 * jurisdiction. It answers four questions declaratively:
 *   1. Which foundational ID API do we verify against, and how? (foundational)
 *   2. What must be true for someone to be issued residency?     (residency)
 *   3. What does the residency Verifiable Credential look like?  (credential)
 *   4. Which subnational units exist?                            (subnationalUnits)
 *
 * No code change is required to add a country whose provider is a normal REST API.
 */

const authSchema = z.object({
  type: z.enum(['none', 'apiKey', 'bearer', 'basic', 'mtls']).default('none'),
  headerName: z.string().optional(),
  secretEnv: z.string().optional(),
  tokenUrl: z.string().optional(),
  clientIdEnv: z.string().optional(),
  clientSecretEnv: z.string().optional(),
});

const inputFieldSchema = z.object({
  key: z.string(),
  label: z.string(),
  required: z.boolean().default(true),
  pattern: z.string().optional(),
  secret: z.boolean().default(false), // e.g. OTP - do not log
});

const foundationalSchema = z.object({
  provider: z.string(), // e.g. NG_NIN, IN_AADHAAR, GENERIC_REST, MOCK
  baseUrl: z.string().optional(),
  auth: authSchema.optional(),
  timeoutMs: z.number().int().positive().optional(),
  /** Fields the citizen must submit; also drives auto-generated UIs. */
  inputs: z.array(inputFieldSchema).default([]),
  request: z
    .object({
      method: z.enum(['GET', 'POST']).default('POST'),
      path: z.string().default(''),
      bodyTemplate: z.record(z.string()).optional(),
      headers: z.record(z.string()).optional(),
    })
    .optional(),
  responseMapping: z.record(z.string()).optional(),
  verifiedFlag: z
    .object({ path: z.string(), equals: z.unknown().optional() })
    .optional(),
  assuranceOnSuccess: z.enum(['none', 'basic', 'verified', 'high']).optional(),
  extra: z.record(z.unknown()).optional(),
});

const residencySchema = z.object({
  /** Minimum foundational assurance required to issue residency. */
  minAssurance: z.enum(['basic', 'verified', 'high']).default('verified'),
  /**
   * How residence in a subnational unit is established. `attestation` means a
   * ward-level operator or existing register vouches; `document` means an uploaded
   * proof; `selfDeclared` is lowest assurance (still recorded, flagged as such).
   */
  proofOfResidence: z
    .enum(['attestation', 'document', 'selfDeclared'])
    .default('attestation'),
  /** Allow provisional issuance offline, to be reconciled when connectivity returns. */
  allowProvisional: z.boolean().default(true),
});

const credentialSchema = z.object({
  /** Issuer DID. did:web is recommended for government issuers. */
  issuerDid: z.string(),
  /** Human-readable issuer name shown to verifiers and holders. */
  issuerName: z.string(),
  /** VC type name appended to VerifiableCredential. */
  type: z.string().default('StateResidencyCredential'),
  /** Validity window in days. */
  validityDays: z.number().int().positive().default(1095),
  /** JSON-LD context URLs for the credential. */
  context: z.array(z.string()).default(['https://www.w3.org/ns/credentials/v2']),
});

const subnationalUnitSchema = z.object({
  code: z.string(), // e.g. KT for Katsina
  name: z.string(),
  parent: z.string().optional(), // country code
  level: z.enum(['state', 'province', 'region', 'lga', 'ward', 'county']),
});

/**
 * Wallet interoperability profile (OpenID4VCI).
 *
 * None of this is Inji-specific: the implementation speaks the standards, and works with
 * any compatible wallet. But the *defaults* below are deliberately the widest possible
 * surface -- both credential formats, three proof algorithms, both wire dialects -- so
 * that the hardest real wallet (MOSIP's Inji, still on Draft 13, hardcoding RS256) works
 * out of the box.
 *
 * That width has a cost, and a deployment should be able to decline to pay it. Every knob
 * here narrows the surface. See docs/INTEROP.md for what each one breaks if you change it.
 */
const walletSchema = z.object({
  /**
   * Credential formats to offer.
   *
   * `ldp_vc` (JSON-LD + Data Integrity) is what wallets accept; Inji rejects
   * `jwt_vc_json` outright. `jwt_vc_json` is the compact, canonicalization-free format
   * that fits in a printed QR code and suits offline verification. Most deployments want
   * both, which is why both are the default.
   */
  formats: z.array(z.enum(['ldp_vc', 'jwt_vc_json'])).nonempty().default(['ldp_vc', 'jwt_vc_json']),

  /**
   * Key-proof algorithms accepted from a wallet.
   *
   * RS256 is here ONLY because the Inji wallet hardcodes it. We would not otherwise
   * accept RSA -- EdDSA keeps credentials small, which matters for QR codes. Remove RS256
   * once the wallets you serve have moved on; nothing else depends on it.
   */
  proofAlgs: z.array(z.enum(['EdDSA', 'ES256', 'RS256'])).nonempty().default(['EdDSA', 'ES256', 'RS256']),

  compatibility: z
    .object({
      /**
       * Accept and answer the OpenID4VCI Draft 13 wire format alongside 1.0.
       *
       * Draft 13 and 1.0 are wire-incompatible (`proof` vs `proofs`, `credential` vs
       * `credentials`). Inji is on Draft 13, so this defaults on. Turning it off narrows
       * the accepted request surface, which is a security improvement -- do it as soon as
       * every wallet you serve is on 1.0.
       */
      draft13: z.boolean().default(true),

      /**
       * Duplicate `c_nonce` and `client_id` into the access token's JWT claims.
       *
       * This is in NO version of the specification. Inji does not read c_nonce from the
       * token response body; it parses the access token and reads the claim from inside.
       * Without this, Inji signs its key proof with the literal string "null" and the
       * citizen sees "enrollment failed". If you do not serve Inji, turn it off: you are
       * otherwise emitting a non-standard claim for no reason.
       */
      cNonceInAccessToken: z.boolean().default(true),
    })
    .default({}),

  offer: z
    .object({
      /** How long a credential offer QR stays valid. Minutes, not hours: it is scanned at a desk. */
      ttlSeconds: z.number().int().positive().default(900),
      /** Digits in the transaction code read out to the citizen. The second factor. */
      txCodeLength: z.number().int().min(4).max(12).default(6),
      /**
       * Wrong-PIN guesses before the offer locks. A short numeric code is only safe if
       * guesses are bounded; raising this materially weakens the second factor.
       */
      maxTxCodeAttempts: z.number().int().min(1).max(20).default(5),
    })
    .default({}),

  /** Access token lifetime. It only has to survive one credential request. */
  accessTokenTtlSeconds: z.number().int().positive().default(600),
  /** c_nonce lifetime. Single-use regardless; this bounds how stale a proof may be. */
  nonceTtlSeconds: z.number().int().positive().default(300),
});

/**
 * A sector relying party for "Sign in with <State>" (OpenID Connect).
 *
 * These used to be a hardcoded list in oidc.provider.ts, which meant adding a sector
 * service to a deployment required a TypeScript edit -- the one place a country was NOT
 * code-free. They are now declared here, alongside everything else about a jurisdiction.
 *
 * The client secret never appears in config. It is read from an environment variable
 * named `<CLIENT_ID>_CLIENT_SECRET` (uppercased), so a secret does not sit in a file that
 * is committed to git.
 */
const relyingPartySchema = z.object({
  /** Stable client_id. Its uppercase form + `_CLIENT_SECRET` names the secret env var. */
  clientId: z.string().min(1),
  /** Shown to the citizen on the consent screen. */
  name: z.string().optional(),
  /**
   * The sector scope this RP is entitled to (e.g. `health`). Added to the standard
   * `openid profile residency` set. Also registered as a supported scope, so a country
   * can introduce a new sector without a code change.
   */
  sector: z.string().min(1),
  /** OAuth redirect URIs. Must be the real callback URLs in production. */
  redirectUris: z.array(z.string()).nonempty(),
  postLogoutRedirectUris: z.array(z.string()).default([]),
});

/** OIDC identity-provider profile: the relying parties this deployment serves. */
const oidcSchema = z.object({
  relyingParties: z.array(relyingPartySchema).default([]),
});

export type RelyingPartyConfig = z.infer<typeof relyingPartySchema>;

/** Presentation profile (OpenID4VP). Deployment-wide; read from the default country. */
const presentationSchema = z.object({
  /** How long a presentation request stays answerable. */
  requestTtlSeconds: z.number().int().positive().default(300),
  /**
   * Query languages to advertise in the request object.
   *
   * DCQL is OpenID4VP 1.0. Presentation Exchange is what wallets mid-migration still
   * understand. Emitting both means we do not have to guess which a wallet speaks.
   */
  query: z
    .array(z.enum(['dcql', 'presentation_definition']))
    .nonempty()
    .default(['dcql', 'presentation_definition']),
});

export const countryConfigSchema = z.object({
  countryCode: z.string().length(2),
  countryName: z.string(),
  defaultSubnationalUnit: z.string().optional(),
  foundational: foundationalSchema,
  residency: residencySchema.default({}),
  credential: credentialSchema,
  // Both default to today's behaviour, so a config that omits them is unchanged.
  wallet: walletSchema.default({}),
  presentation: presentationSchema.default({}),
  // Sign-in relying parties. Empty by default: a deployment that does not use SSO simply
  // omits this, and no RPs are registered.
  oidc: oidcSchema.default({}),
  subnationalUnits: z.array(subnationalUnitSchema).default([]),
});

export type WalletProfile = z.infer<typeof walletSchema>;
export type PresentationProfile = z.infer<typeof presentationSchema>;

export type CountryConfig = z.infer<typeof countryConfigSchema>;

export function parseCountryConfig(raw: unknown): CountryConfig {
  return countryConfigSchema.parse(raw);
}

/** Load and validate every YAML file in a directory into a keyed map. */
export function loadCountryConfigs(dir: string): Map<string, CountryConfig> {
  const map = new Map<string, CountryConfig>();
  for (const file of readdirSync(dir)) {
    if (!/\.(ya?ml)$/i.test(file)) continue;
    const raw = loadYaml(readFileSync(join(dir, file), 'utf8'));
    const cfg = parseCountryConfig(raw);
    map.set(cfg.countryCode.toUpperCase(), cfg);
  }
  return map;
}
