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

const datasetSchema = z.object({
  path: z.string(),
  format: z.enum(['csv', 'json', 'yaml']).optional(),
  recordsPath: z.string().optional(),
  keyField: z.string(),
  identifierKey: z.string().optional(),
  matchFields: z
    .array(z.object({ identifierKey: z.string(), recordField: z.string() }))
    .optional(),
  caseInsensitive: z.boolean().default(false),
});

const foundationalSchema = z.object({
  // e.g. NG_NIN, IN_AADHAAR, GENERIC_REST (JSON API), GENERIC_XML (XML/SOAP API),
  // DATASET_FILE / IMPORT (register extract), MOCK
  provider: z.string(),
  baseUrl: z.string().optional(),
  auth: authSchema.optional(),
  timeoutMs: z.number().int().positive().optional(),
  /** Response wire format; `xml` uses the same mapping dot-paths over parsed elements. */
  responseFormat: z.enum(['json', 'xml']).optional(),
  /** XML-parsing options (XML/SOAP providers). */
  xml: z.object({ stripNamespaces: z.boolean().default(true) }).optional(),
  /** Imported register extract, for the DATASET_FILE / IMPORT provider. */
  dataset: datasetSchema.optional(),
  /** Fields the citizen must submit; also drives auto-generated UIs. */
  inputs: z.array(inputFieldSchema).default([]),
  request: z
    .object({
      method: z.enum(['GET', 'POST']).default('POST'),
      path: z.string().default(''),
      bodyTemplate: z.record(z.string()).optional(),
      /** Raw request body (e.g. a SOAP envelope) with {identifiers.x} placeholders. */
      bodyRaw: z.string().optional(),
      /** Content-Type for a raw body; defaults to text/xml for XML providers. */
      contentType: z.string().optional(),
      headers: z.record(z.string()).optional(),
    })
    .optional(),
  responseMapping: z.record(z.string()).optional(),
  verifiedFlag: z
    .object({ path: z.string(), equals: z.unknown().optional() })
    .optional(),
  assuranceOnSuccess: z.enum(['none', 'basic', 'verified', 'high']).optional(),
  /**
   * True only for providers whose verification authenticates the APPLICANT as the owner
   * (an eID / OIDC redirect, or an OTP to the device registered against the record). Such
   * a provider attests `authoritative_authentication` binding on success. A lookup-only
   * provider (a NIN/registry match) must leave this false: passing the lookup is not
   * proof the applicant owns the identity.
   */
  authenticatesApplicant: z.boolean().default(false),
  extra: z.record(z.unknown()).optional(),
});

const bindingMethodEnum = z.enum([
  'authoritative_authentication',
  'face_match',
  'fingerprint_match',
  'attended_comparison',
]);

const residenceMethodEnum = z.enum([
  'register_declared_residence',
  'authority_attestation',
  'document',
  'geospatial_match',
]);

const residenceLevelEnum = z.enum(['RAL0', 'RAL1', 'RAL2', 'RAL3']);

/**
 * Proof-of-residence policy.
 *
 * Where `applicantBinding` gates "does the applicant own this identity?", this gates "does
 * the applicant actually reside in the claimed unit?". Both are recorded on every
 * credential; setting `required` turns residence into an accept/reject gate at issuance.
 *
 * `acceptFoundationalResidence` opts in to auto-collecting the residence locality the
 * foundational provider returns (never the origin field) as `register_declared_residence`
 * evidence -- capped low by default because such a field is typically self-declared to the
 * source register, undated, and coarser than a ward. `unitMatchRequired` forces that
 * evidence to reconcile to the claimed unit before it counts.
 */
const residencePolicySchema = z.object({
  required: z.boolean().default(false),
  targetLevel: residenceLevelEnum.default('RAL1'),
  acceptedMethods: z
    .array(residenceMethodEnum)
    .default(['register_declared_residence', 'authority_attestation', 'document', 'geospatial_match']),
  unitMatchRequired: z.boolean().default(true),
  recencyDays: z.number().int().positive().optional(),
  methodCeiling: z.record(residenceMethodEnum, residenceLevelEnum).optional(),
  acceptFoundationalResidence: z.boolean().default(false),
});

export type ResidencePolicyConfig = z.infer<typeof residencePolicySchema>;

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
  /**
   * Applicant -> identity binding policy.
   *
   * Foundational verification proves the identity RECORD is genuine; on its own it does
   * NOT prove the applicant OWNS it. When `required` is true, issuance is refused unless
   * an accepted binding method was achieved -- either attested by the foundational
   * provider (authoritative_authentication) or supplied by the enrolment channel
   * (attended_comparison, face_match, fingerprint_match). Leaving `required` false keeps
   * the binding recorded on every credential but does not gate issuance on it; that is
   * appropriate for demos and low-assurance tiers, not for a real resident credential.
   */
  applicantBinding: z
    .object({
      required: z.boolean().default(false),
      acceptedMethods: z
        .array(bindingMethodEnum)
        .default([
          'authoritative_authentication',
          'face_match',
          'fingerprint_match',
          'attended_comparison',
        ]),
    })
    .default({}),
  /**
   * Proof-of-residence policy. Omit it entirely and residence is recorded as self-declared
   * (RAL0) and never gated -- exactly today's behaviour. Opt in to enforce it.
   */
  residence: residencePolicySchema.default({}),
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

/**
 * A public Ed25519 JWK belonging to a peer issuer we federate with.
 *
 * Public material only: a `d` component would mean another issuer's PRIVATE key is sitting
 * in this deployment's config, which is never right, so it is rejected at load time. A
 * `kid` is required because the trust list selects a key by the `kid` in a credential's
 * header when one is present.
 */
const federatedJwkSchema = z
  .object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: z.string().min(1),
    kid: z.string().min(1),
    d: z.undefined({ invalid_type_error: 'a federated issuer key must be PUBLIC (no "d")' }).optional(),
  })
  .strict();

/**
 * A peer issuer this deployment trusts. The basis of federation: a residency credential
 * signed by another state's key verifies here because that state's DID and public key(s)
 * are listed, exactly as this deployment trusts its own key.
 */
const federatedIssuerSchema = z.object({
  /** The peer's issuer DID, matched against the `iss`/`kid` of an inbound credential. */
  did: z.string().min(1),
  /** Human-readable label, for trust-registry displays and audit. */
  name: z.string().optional(),
  /** The peer's public signing keys: current first, then retired ones (rotation-safe). */
  publicJwks: z.array(federatedJwkSchema).nonempty(),
  /**
   * Where the peer publishes its Bitstring Status List, if it does. When set, a synced
   * snapshot lets this deployment check revocation of the peer's credentials; when absent,
   * the peer's credentials verify for authenticity but their revocation cannot be
   * confirmed here (the offline verify path says so; the online presentation path fails
   * closed, exactly as it does for our own credentials).
   */
  statusListUrl: z.string().url().optional(),
});

/**
 * Cross-issuer federation (deployment-wide, read from the default config like `oidc`).
 *
 * A subnational deployment is single-issuer by default: it trusts only credentials it
 * signed itself. In a federation -- several states on the same platform, or a national
 * umbrella recognising state issuers -- a credential from one issuer must verify at
 * another. Listing a peer here adds its keys to the same trust map that holds our own,
 * so the verifier accepts its credentials without any code change. Trust is explicit and
 * allow-listed: an issuer not listed here is `UNTRUSTED_ISSUER`, which is the safe default
 * for a system where accepting a forged issuer means accepting a forged residency.
 */
const federationSchema = z.object({
  trustedIssuers: z.array(federatedIssuerSchema).default([]),
});

export type FederatedIssuerConfig = z.infer<typeof federatedIssuerSchema>;
export type FederationConfig = z.infer<typeof federationSchema>;

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
   * `openid profile` set. Also registered as a supported scope, so a country can
   * introduce a new sector without a code change.
   */
  sector: z.string().min(1),
  /**
   * Scopes this RP may request, beyond `openid` and its own sector.
   *
   * `residency` is the one that matters and it is NOT granted by default. That scope
   * releases `resident_id`, which is the same value for a given citizen at every service
   * -- so while it was handed to every RP automatically, any two services could join
   * their records on it and reconstruct a cross-government view of a person. Pairwise
   * `sub` values do not fix that on their own; the correlatable claim has to stop being
   * universally available too.
   *
   * Grant it only to relying parties with a lawful basis for holding the residency
   * number itself. A service that merely needs to know someone is a resident of a unit
   * should take `profile` and its sector scope and read the assurance claims instead.
   */
  scopes: z.array(z.enum(['profile', 'residency', 'offline_access'])).default(['profile']),
  /** OAuth redirect URIs. Must be the real callback URLs in production. */
  redirectUris: z.array(z.string()).nonempty(),
  postLogoutRedirectUris: z.array(z.string()).default([]),
});

/** OIDC identity-provider profile: the relying parties this deployment serves. */
const oidcSchema = z.object({
  relyingParties: z.array(relyingPartySchema).default([]),
  /**
   * Subject identifier type.
   *
   * `pairwise` derives a different `sub` for each relying party, so the identifier one
   * service knows a citizen by is useless to another. `public` emits the residency id
   * itself at every service, which makes cross-service correlation trivial for anyone who
   * can compare two databases -- exactly what independent MDAs must not be able to do.
   *
   * Defaults to pairwise. Switching to `public` is a deliberate downgrade and should only
   * be done for a legacy RP that cannot be migrated.
   */
  subjectType: z.enum(['pairwise', 'public']).default('pairwise'),
});

export type RelyingPartyConfig = z.infer<typeof relyingPartySchema>;
export type OidcProfile = z.infer<typeof oidcSchema>;

/**
 * How members of staff authenticate to the privileged endpoints.
 *
 * `oidc` is the mode a real deployment runs: staff identity, password policy, MFA and
 * de-provisioning stay in the ministry's own directory, and this system holds no staff
 * credentials. `local` exists for deployments with no IdP yet -- it is a full
 * implementation (scrypt, TOTP, lockout, per-operator API keys with rotation), but it
 * makes this system a staff credential store, which is a liability an IdP removes.
 *
 * `sharedKey` is the legacy single ADMIN_API_KEY. It carries no identity: every action
 * audits to the same actor, there are no roles, and rotation means restarting with every
 * client cutting over at once. It is retained so existing deployments keep working and
 * warns on every boot.
 */
const operatorAuthSchema = z.object({
  mode: z.enum(['oidc', 'local', 'sharedKey']).default('sharedKey'),
  /** Issuer name shown in operators' authenticator apps. */
  issuerName: z.string().default('OpenResidency'),
  oidc: z
    .object({
      issuer: z.string(),
      audience: z.string(),
      roleClaim: z.string().default('roles'),
      nameClaim: z.string().default('preferred_username'),
      /** Maps the directory's own group names onto OpenResidency roles. */
      roleMap: z.record(z.string()).default({}),
      jwksUri: z.string().optional(),
    })
    .optional(),
  local: z
    .object({
      /** Refuse logins from accounts that have not enrolled a second factor. */
      requireMfa: z.boolean().default(true),
      sessionTtlSeconds: z.number().int().positive().default(8 * 3600),
    })
    .default({}),
});

export type OperatorAuthConfig = z.infer<typeof operatorAuthSchema>;

/**
 * Outbound messaging: how a one-time code or a status notice reaches a citizen's handset.
 *
 * Omit this block and delivery is disabled -- the sign-in fallback simply does not work,
 * which is the honest failure. It must never quietly degrade to logging the code, which
 * is what the previous default did.
 */
const messagingSchema = z.object({
  provider: z
    .enum(['LOG', 'GENERIC_HTTP', 'AFRICASTALKING', 'TWILIO', 'TERMII'])
    .default('LOG'),
  /** Sender id / short code / from-number. For Twilio this is the Account SID in the path. */
  sender: z.string().optional(),
  baseUrl: z.string().optional(),
  timeoutMs: z.number().int().positive().optional(),
  auth: z
    .object({
      type: z.enum(['none', 'apiKey', 'bearer', 'basic']).default('none'),
      headerName: z.string().optional(),
      secretEnv: z.string().optional(),
      usernameEnv: z.string().optional(),
    })
    .optional(),
  /** Request shape. Omit it for a preset provider; supply it for GENERIC_HTTP. */
  request: z
    .object({
      method: z.enum(['GET', 'POST']).default('POST'),
      path: z.string().default(''),
      bodyTemplate: z.record(z.string()).optional(),
      form: z.boolean().default(false),
      headers: z.record(z.string()).optional(),
      messageIdPath: z.string().optional(),
      successFlag: z.object({ path: z.string(), equals: z.unknown().optional() }).optional(),
    })
    .optional(),
  /** SMS body. {code} and {issuer} are substituted. */
  otpTemplate: z
    .string()
    .default('Your {issuer} sign-in code is {code}. It expires in 5 minutes. Do not share it.'),
  /**
   * Acknowledge that LOG writes live one-time codes to the service log. Required to boot
   * with provider: LOG, so the dev stub cannot be inherited silently by a config copied
   * into production.
   */
  acknowledgeInsecureLogProvider: z.boolean().default(false),
});

export type MessagingConfig = z.infer<typeof messagingSchema>;

/** Where a resident's phone number comes from at send time. See contact-directory.ts. */
const contactDirectorySchema = z.object({
  mode: z.enum(['none', 'encrypted', 'external']).default('none'),
  external: z
    .object({
      baseUrl: z.string(),
      path: z.string().default('/contacts/{residentId}'),
      responsePath: z.string().default('msisdn'),
      secretEnv: z.string().optional(),
      headerName: z.string().optional(),
      timeoutMs: z.number().int().positive().optional(),
    })
    .optional(),
});

export type ContactDirectoryConfig = z.infer<typeof contactDirectorySchema>;

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

/**
 * Resident ID format ruleset.
 *
 * The default reproduces the original `KT-7F3A-9K2P-4` scheme exactly. A state can instead
 * declare its own house style -- e.g. a 12-digit numeric KRID with a Luhn check. There is
 * deliberately NO free-form template: the random body is the only variable part, so the
 * foundational number can never be embedded in a public identifier.
 */
const idAlphabetEnum = z.enum(['crockford32', 'numeric', 'alphanumeric', 'hex']);
const checksumEnum = z.enum(['crockford-sha256', 'luhn', 'mod97-10', 'none']);
const ID_ALPHABET_SIZE: Record<string, number> = {
  crockford32: 32,
  numeric: 10,
  alphanumeric: 36,
  hex: 16,
};
/** Minimum bits of randomness in the body; ~32 admits a 12-digit numeric KRID. */
const MIN_ID_ENTROPY_BITS = 32;

const residentIdSchema = z
  .object({
    alphabet: idAlphabetEnum.default('crockford32'),
    customAlphabet: z.string().min(2).optional(),
    groups: z.array(z.number().int().positive()).nonempty().default([4, 4]),
    separator: z.string().default('-'),
    case: z.enum(['upper', 'lower']).default('upper'),
    prefix: z
      .object({
        mode: z.enum(['unit', 'static', 'country', 'none']).default('unit'),
        value: z.string().optional(),
      })
      .default({}),
    checkDigit: z
      .object({
        enabled: z.boolean().default(true),
        algorithm: checksumEnum.default('crockford-sha256'),
      })
      .default({}),
  })
  .superRefine((v, ctx) => {
    // Collision safety: too short a random body risks duplicate IDs.
    const size =
      v.customAlphabet && v.customAlphabet.length >= 2
        ? v.customAlphabet.length
        : ID_ALPHABET_SIZE[v.alphabet];
    const bodyLen = v.groups.reduce((a, b) => a + b, 0);
    const bits = bodyLen * Math.log2(size);
    if (bits < MIN_ID_ENTROPY_BITS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['groups'],
        message: `resident id body has ~${bits.toFixed(0)} bits of entropy; lengthen groups to reach >= ${MIN_ID_ENTROPY_BITS} bits`,
      });
    }
    // Numeric checksums operate on digits, so they need a numeric body and no alpha prefix.
    const numericChecksum =
      v.checkDigit.algorithm === 'luhn' || v.checkDigit.algorithm === 'mod97-10';
    if (v.checkDigit.enabled && numericChecksum) {
      if (v.alphabet !== 'numeric' || v.customAlphabet) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['checkDigit', 'algorithm'],
          message: `${v.checkDigit.algorithm} requires alphabet: numeric`,
        });
      }
      const alphaPrefix =
        v.prefix.mode === 'unit' ||
        v.prefix.mode === 'country' ||
        (v.prefix.mode === 'static' && /\D/.test(v.prefix.value ?? ''));
      if (alphaPrefix) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['prefix'],
          message: `${v.checkDigit.algorithm} cannot be computed over a non-numeric prefix; use prefix.mode: none`,
        });
      }
    }
    if (v.prefix.mode === 'static' && !v.prefix.value) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['prefix', 'value'],
        message: 'prefix.mode: static requires prefix.value',
      });
    }
  });

export type ResidentIdConfig = z.infer<typeof residentIdSchema>;

const subnationalUnitSchema = z.object({
  code: z.string(), // e.g. KT for Katsina
  name: z.string(),
  parent: z.string().optional(), // country code
  level: z.enum(['state', 'province', 'region', 'lga', 'ward', 'county']),
  /**
   * Per-unit Resident ID format. A federation lets each subnational unit run its own
   * numbering scheme -- one state on the Crockford default, another on a statutory 12-digit
   * numeric ID -- so a unit may override the country format wholesale. Omit it and the unit
   * inherits the country-level `residentId`. When present, it is a complete ruleset (each
   * omitted field takes the same default as the country format) and is validated the same
   * way, so a unit cannot configure an unsafe or incoherent format.
   */
  residentId: residentIdSchema.optional(),
});

export const countryConfigSchema = z
  .object({
  countryCode: z.string().length(2),
  countryName: z.string(),
  defaultSubnationalUnit: z.string().optional(),
  foundational: foundationalSchema,
  residency: residencySchema.default({}),
  credential: credentialSchema,
  // Country-default Resident ID format; a subnationalUnit may override it. Omit it for the
  // default KT-XXXX-XXXX-C scheme.
  residentId: residentIdSchema.default({}),
  // Both default to today's behaviour, so a config that omits them is unchanged.
  wallet: walletSchema.default({}),
  presentation: presentationSchema.default({}),
  // Sign-in relying parties. Empty by default: a deployment that does not use SSO simply
  // omits this, and no RPs are registered.
  oidc: oidcSchema.default({}),
  // Deployment-wide profiles. Read from the default (first) country config, the same way
  // the presentation profile is. Omit them and you get: shared-key operator auth with a
  // boot warning, no messaging, and no contact directory.
  operatorAuth: operatorAuthSchema.default({}),
  messaging: messagingSchema.optional(),
  contactDirectory: contactDirectorySchema.default({}),
  // Cross-issuer trust. Deployment-wide, read from the default config. Empty by default:
  // a deployment trusts only its own issuer until it names peers here.
  federation: federationSchema.default({}),
  subnationalUnits: z.array(subnationalUnitSchema).default([]),
  })
  .superRefine((v, ctx) => {
    // A mode is only meaningful with the block that configures it. Catching this at load
    // time turns a silent fallback to shared-key auth into a refusal to start.
    if (v.operatorAuth.mode === 'oidc' && !v.operatorAuth.oidc) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['operatorAuth', 'oidc'],
        message: 'operatorAuth.mode: oidc requires an operatorAuth.oidc block (issuer, audience)',
      });
    }
    if (v.contactDirectory.mode === 'external' && !v.contactDirectory.external) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['contactDirectory', 'external'],
        message: 'contactDirectory.mode: external requires a contactDirectory.external block',
      });
    }
    // The dev sender writes live one-time codes to stdout. Requiring an explicit
    // acknowledgement is what stops a config copied from the demo into a real deployment
    // from silently disabling the fallback factor's confidentiality.
    if (v.messaging?.provider === 'LOG' && !v.messaging.acknowledgeInsecureLogProvider) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['messaging', 'provider'],
        message:
          'messaging.provider: LOG writes one-time codes to the service log. Set ' +
          'messaging.acknowledgeInsecureLogProvider: true to confirm this is a development ' +
          'deployment, or configure a real aggregator.',
      });
    }
    if (v.messaging && v.messaging.provider !== 'LOG' && v.contactDirectory.mode === 'none') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['contactDirectory', 'mode'],
        message:
          'messaging is configured but contactDirectory.mode is none, so no message can ever ' +
          'be addressed. Set a contact directory, or remove the messaging block.',
      });
    }
    // Pairwise subjects are undone by handing every RP the correlatable claim anyway, so
    // flag the combination rather than letting it look like a privacy control.
    if (v.oidc.subjectType === 'pairwise') {
      const all = v.oidc.relyingParties;
      const withResidency = all.filter((rp) => rp.scopes.includes('residency'));
      if (all.length > 1 && withResidency.length === all.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['oidc', 'relyingParties'],
          message:
            'every relying party is granted the `residency` scope, which releases the same ' +
            'resident_id to all of them -- so pairwise subject identifiers prevent no ' +
            'correlation. Grant `residency` only to RPs with a lawful basis for the number.',
        });
      }
    }
  });

export type WalletProfile = z.infer<typeof walletSchema>;
export type PresentationProfile = z.infer<typeof presentationSchema>;

export type CountryConfig = z.infer<typeof countryConfigSchema>;

export function parseCountryConfig(raw: unknown): CountryConfig {
  return countryConfigSchema.parse(raw);
}

/**
 * Load and validate every YAML file in a directory into a keyed map.
 *
 * The file list is sorted, because insertion order is load-bearing: several
 * deployment-wide profiles (the presentation profile, operator authentication, messaging)
 * are read from the FIRST config loaded. `readdirSync` gives no ordering guarantee across
 * platforms or filesystems, so without this the mode a deployment runs in could differ
 * between two machines holding identical files.
 */
export function loadCountryConfigs(dir: string): Map<string, CountryConfig> {
  const map = new Map<string, CountryConfig>();
  for (const file of readdirSync(dir).sort()) {
    if (!/\.(ya?ml)$/i.test(file)) continue;
    const raw = loadYaml(readFileSync(join(dir, file), 'utf8'));
    const cfg = parseCountryConfig(raw);
    map.set(cfg.countryCode.toUpperCase(), cfg);
  }
  return map;
}
