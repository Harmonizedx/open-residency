// SPDX-License-Identifier: Apache-2.0
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { load as loadYaml } from 'js-yaml';
import { z } from 'zod';
import { permitsAutomatedDecisions } from '../residency/decision-mode';
import { CONSENT_LEGAL_BASIS_ID } from '../consent/legal-basis';
import { LEGACY_SUITES } from '../credentials/ld-suites';

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
  /**
   * Retry policy for transient gateway failures.
   *
   * A national ID gateway is another government's server on another government's network,
   * reached from a desk that may be on a poor rural link, so a dropped connection is an
   * ordinary event rather than an exceptional one. Only transport failures, 429 and 5xx are
   * retried; a 4xx refusal and a clean "no match" are answers, not failures, and repeating
   * them spends a paid call to be told the same thing.
   */
  retry: z
    .object({
      attempts: z.number().int().min(1).max(10).optional(),
      baseDelayMs: z.number().int().nonnegative().optional(),
      maxDelayMs: z.number().int().nonnegative().optional(),
    })
    .optional(),
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
      bodyTemplate: z.record(z.string(), z.string()).optional(),
      /** Raw request body (e.g. a SOAP envelope) with {identifiers.x} placeholders. */
      bodyRaw: z.string().optional(),
      /** Content-Type for a raw body; defaults to text/xml for XML providers. */
      contentType: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
    })
    .optional(),
  responseMapping: z.record(z.string(), z.string()).optional(),
  verifiedFlag: z
    .object({ path: z.string(), equals: z.unknown().optional() })
    .optional(),
  /**
   * The assurance a successful verification by THIS provider establishes.
   *
   * Required, and deliberately so. It was optional, and `mapping.ts` resolved an omitted
   * value to `'verified'` -- the second-highest rung, reached by saying nothing. A
   * deployment that forgot to state what its identity source actually proves was silently
   * credited with having proved a great deal, and the value is released to every relying
   * party over SSO as `assurance_level`.
   *
   * There is no safe default here: only the deployer knows what their register, eID or
   * field-verification process establishes. So the config must say, and a config that does
   * not is rejected at load rather than guessed at during issuance. Every shipped config
   * already declares it.
   */
  assuranceOnSuccess: z.enum(['none', 'basic', 'verified', 'high'], {
    // zod 4 collapsed required_error and invalid_type_error into one `error`, which is used
    // for a MISSING value and an INVALID one alike. The wording has to hold for both: the
    // old text said only "is required", which would now misreport a supplied-but-bogus value
    // as an absent one, sending the deployer looking for a key that is already there.
    error:
      'foundational.assuranceOnSuccess must state what a successful verification by this ' +
      'provider proves (none | basic | verified | high). It is released to relying parties ' +
      'as assurance_level, so it is neither optional nor inferred.',
  }),
  /**
   * True only for providers whose verification authenticates the APPLICANT as the owner
   * (an eID / OIDC redirect, or an OTP to the device registered against the record). Such
   * a provider attests `authoritative_authentication` binding on success. A lookup-only
   * provider (a NIN/registry match) must leave this false: passing the lookup is not
   * proof the applicant owns the identity.
   */
  authenticatesApplicant: z.boolean().default(false),
  extra: z.record(z.string(), z.unknown()).optional(),
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
  /**
   * What residency is anchored to in this jurisdiction.
   *
   * `unit` -- membership of an administrative unit. The default, and what residency means in
   * Nigeria and much of the world where addressing is partial or informal.
   *
   * `address` -- registration at a specific address, with the unit still required to agree.
   * What residency means under Germany's Bundesmeldegesetz, Japan's jūminhyō and the Nordic
   * population registers, where "which state do you live in" is not a weaker residency but
   * simply not residency at all.
   *
   * See `src/core/proofing/address.ts`. Defaulted so no existing deployment changes meaning.
   */
  anchor: z.enum(['unit', 'address']).default('unit'),
  recencyDays: z.number().int().positive().optional(),
  methodCeiling: z.record(residenceMethodEnum, residenceLevelEnum).optional(),
  acceptFoundationalResidence: z.boolean().default(false),
});

export type ResidencePolicyConfig = z.infer<typeof residencePolicySchema>;

/**
 * Retention policy for this jurisdiction.
 *
 * Every period defaults to null -- no automatic expiry -- because a retention period is a
 * controller's decision against their own law. A default number here would be this software
 * quietly setting policy for a government, and the wrong direction to be wrong in: too short
 * destroys records a citizen may need for an appeal, too long is itself a breach.
 */
const retentionSchema = z.object({
  /** Days to keep a residency record, measured from creation. Null = keep indefinitely. */
  residencyDays: z.number().int().positive().nullable().default(null),
  /**
   * Suspend all retention deletion. Set during litigation, an open appeal, or a regulator's
   * request; the sweep refuses to run at all rather than guess which records are implicated.
   */
  legalHold: z.boolean().default(false),
});

export type RetentionConfig = z.infer<typeof retentionSchema>;

const residencySchema = z.object({
  /** Retention periods. Defaults to no automatic expiry — see retentionSchema. */
  retention: retentionSchema.prefault({}),
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
   * How long a provisionally-issued residency may go unconfirmed before its credential is
   * revoked. Omit to let provisional records stand indefinitely.
   *
   * A provisional record is issued on trust that the live authority will later agree. If
   * nobody ever checks, that trust never expires by itself, and the register fills with
   * credentials asserting a residency no authority has confirmed — which is what would make
   * "provisional" and "verified" mean the same thing in practice.
   */
  provisionalMaxAgeDays: z.number().int().positive().optional(),
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
    .prefault({}),
  /**
   * Proof-of-residence policy. Omit it entirely and residence is recorded as self-declared
   * (RAL0) and never gated -- exactly today's behaviour. Opt in to enforce it.
   */
  residence: residencePolicySchema.prefault({}),
  /**
   * How a person obtains human review of a decision the software took alone.
   *
   * REQUIRED when this jurisdiction's accepted methods permit a fully automated decision --
   * enforced below, at config load, so a deployment cannot begin deciding before it can say
   * where an affected person goes.
   *
   * Not derivable, unlike the decision mode itself: only the jurisdiction knows whether that
   * is an office, a form, a phone line or a statutory tribunal. Free text for the same reason
   * the appeal path is.
   */
  humanReview: z
    .object({
      /** Where and how to request that a person reconsiders. Shown to the applicant. */
      path: z.string().min(1),
      /**
       * How long the jurisdiction undertakes to take. Recorded because an unbounded right to
       * review is not much of a right; omitted where the law sets no period.
       */
      withinDays: z.number().int().positive().optional(),
    })
    .optional(),
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
  /**
   * Where a holder contests a revocation. ORCS §10 requires an appeal path be preserved with
   * every revocation, and only the jurisdiction knows what its own is -- an office, a form, a
   * statute reference. Left unset, revocations record that none has been published, which is
   * a finding an operator can act on rather than a silent gap.
   */
  appealPath: z.string().optional(),
  /**
   * The reason recorded when a caller revokes without supplying one. A deployment that
   * revokes through the plain endpoint still has to put something truthful in the record.
   */
  defaultRevocationReason: z.string().optional(),
});

/**
 * A public Ed25519 JWK belonging to a peer issuer we federate with.
 *
 * Public material only: a `d` component would mean another issuer's PRIVATE key is sitting
 * in this deployment's config, which is never right, so it is rejected at load time. A
 * `kid` is required because the trust list selects a key by the `kid` in a credential's
 * header when one is present.
 */
const NO_PRIVATE_KEY = { error: 'a federated issuer key must be PUBLIC (no "d")' } as const;

const federatedEd25519JwkSchema = z
  .object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: z.string().min(1),
    kid: z.string().min(1),
    d: z.undefined(NO_PRIVATE_KEY).optional(),
  })
  .strict();

/**
 * An RSA public key belonging to a peer issuer.
 *
 * We sign with Ed25519 and will not do otherwise. But an issuer we do not control may sign
 * with RSA -- `RsaSignature2018` is what a good deal of the deployed MOSIP/Inji-era
 * credential estate carries -- and a trust list that cannot express the peer's key cannot
 * verify the peer's credentials. Accepting an RSA key for VERIFICATION says nothing about
 * what this deployment issues.
 *
 * `d` is refused here for the same reason as above, and so are the other private
 * components: an RSA private key is `d` plus `p`/`q`/`dp`/`dq`/`qi`, and a schema that
 * rejected only `d` would still let most of a private key sit in a config file.
 */
const federatedRsaJwkSchema = z
  .object({
    kty: z.literal('RSA'),
    n: z.string().min(1),
    e: z.string().min(1),
    kid: z.string().min(1),
    d: z.undefined(NO_PRIVATE_KEY).optional(),
    p: z.undefined(NO_PRIVATE_KEY).optional(),
    q: z.undefined(NO_PRIVATE_KEY).optional(),
    dp: z.undefined(NO_PRIVATE_KEY).optional(),
    dq: z.undefined(NO_PRIVATE_KEY).optional(),
    qi: z.undefined(NO_PRIVATE_KEY).optional(),
  })
  .strict();

const federatedJwkSchema = z.union([federatedEd25519JwkSchema, federatedRsaJwkSchema]);

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
  /**
   * Accept this peer's status list unsigned. Off by default, and it should stay off.
   *
   * A revocation list cached without a verifiable proof is authenticated only by TLS to
   * whatever host answered, so anyone able to spoof that host can serve a list that silently
   * UN-REVOKES the peer's credentials. This exists for a peer still publishing bare JSON, and
   * turning it on is a deliberate, per-peer, visible decision to trust transport instead of a
   * signature.
   */
  allowUnsignedStatusList: z.boolean().default(false),
  /**
   * Linked-data proof suites accepted from THIS peer, beyond the one we issue.
   *
   * Empty by default, which means a peer's JSON-LD credentials must carry the current
   * suite (`DataIntegrityProof` / `eddsa-rdfc-2022`). The legacy suites are listed per
   * peer rather than switched on globally because each one is an accommodation to a
   * specific issuer's stack: a deployment federating with one MOSIP-era issuer should not
   * thereby start accepting 2018-era proofs from every other peer in its trust list.
   *
   * Verification only. Nothing here changes what this deployment issues.
   */
  acceptedProofSuites: z.array(z.enum(LEGACY_SUITES)).default([]),
  /**
   * The peer's own JSON-LD context documents, pinned.
   *
   * An outside issuer defines its credential terms in a context it hosts. Canonicalizing
   * its credentials requires that document, and the loader refuses to fetch anything at
   * verification time -- for determinism, for offline verifiers, and because whoever
   * serves a context can change what the signature is understood to cover. So the peer's
   * context is pinned here, next to the peer's keys, and reviewed with them.
   */
  contexts: z
    .array(
      z.object({
        url: z.string().url(),
        /** The context document itself, inline: `{ "@context": { ... } }`. */
        document: z.record(z.string(), z.unknown()),
      }),
    )
    .default([]),
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
    .prefault({}),

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
    .prefault({}),

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
 * An EXTERNAL OpenID Provider residents may sign in with (deployment-wide). OPTIONAL.
 *
 * Where `oidc` above describes this deployment acting AS a provider, this describes it
 * acting as a relying party at somebody else's -- a MOSIP eSignet instance, a national eID,
 * any conformant OP. A jurisdiction whose residents already have a national identity
 * provider should not make them prove themselves twice, and an upstream sign-in binds the
 * applicant to the identity far more strongly than any registry lookup can.
 *
 * Absent means no external provider, which is the default: nothing here is required to run.
 */
const upstreamOidcSchema = z.object({
  issuer: z.string().min(1),
  authorizationEndpoint: z.string().url(),
  tokenEndpoint: z.string().url(),
  userinfoEndpoint: z.string().url().optional(),
  /**
   * The provider's signing keys, PINNED rather than fetched from its `jwks_uri`.
   *
   * Whoever answers for that URL at verification time decides which id_tokens we believe.
   * A deployment tracking a rotating provider refreshes these out of band and restarts --
   * slower than a live fetch, and a far smaller trust surface.
   */
  jwks: z.array(z.record(z.string(), z.unknown())).nonempty(),
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  scopes: z.array(z.string()).default([]),
  /** Requested acr values, in preference order. */
  acrValues: z.array(z.string()).default([]),
  /**
   * What each acr the provider may return is worth here.
   *
   * Required and non-empty, with no inferred ordering. Only the deployer knows what their
   * provider's "password" or "generated-code" actually establishes about the person, and
   * the value reaches every relying party as `assurance_level`. An acr the provider returns
   * that is not listed here fails the sign-in rather than being credited with something.
   */
  acrMapping: z
    .array(
      z.object({
        acr: z.string().min(1),
        assurance: z.enum(['none', 'basic', 'verified', 'high']),
      }),
    )
    .nonempty(),
  /**
   * Env var names holding the RP's private keys -- never the keys themselves. Config is
   * reviewed, printed and committed; a private key must not be any of those things.
   */
  clientAssertionKeyEnv: z.string().min(1),
  clientAssertionAlg: z.string().default('RS256'),
  /** Needed only if the provider encrypts its userinfo response (eSignet does). */
  userinfoDecryptionKeyEnv: z.string().optional(),
  claimMapping: z.record(z.string(), z.string()).optional(),
  clockToleranceSeconds: z.number().int().nonnegative().default(60),
  timeoutMs: z.number().int().positive().default(8000),
});

export type UpstreamOidcProfile = z.infer<typeof upstreamOidcSchema>;

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
      roleMap: z.record(z.string(), z.string()).default({}),
      jwksUri: z.string().optional(),
    })
    .optional(),
  local: z
    .object({
      /** Refuse logins from accounts that have not enrolled a second factor. */
      requireMfa: z.boolean().default(true),
      sessionTtlSeconds: z.number().int().positive().default(8 * 3600),
    })
    .prefault({}),
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
      bodyTemplate: z.record(z.string(), z.string()).optional(),
      form: z.boolean().default(false),
      headers: z.record(z.string(), z.string()).optional(),
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

/**
 * Biometric authority (deployment-wide, read from the default config).
 *
 * The attested-match authority used for the AAL3 sign-in step-up. Bring-your-own, exactly
 * like `foundational` and `messaging`: point `GENERIC_HTTP` at whatever attests matches for
 * the jurisdiction (a national ABIS, a MOSIP gateway, a vendor matcher behind an HTTP shim),
 * declare where the yes/no verdict lives in the response, and no code changes. `NONE` (the
 * default) means the deployment offers no biometric step-up; `MOCK` is dev/test only and
 * refuses to run in production.
 *
 * The matcher this configures is FAIL-CLOSED by contract: any error, timeout, or
 * unexpected response is a non-match, never a pass. The live capture is sent only to the
 * authority and is never stored, logged, or audited.
 */
const biometricSchema = z.object({
  provider: z.enum(['NONE', 'MOCK', 'GENERIC_HTTP']).default('NONE'),
  baseUrl: z.string().optional(),
  timeoutMs: z.number().int().positive().optional(),
  /** Attesting-authority name for the audit trail (or read from the response). */
  source: z.string().optional(),
  auth: z
    .object({
      type: z.enum(['none', 'apiKey', 'bearer', 'basic']).default('none'),
      headerName: z.string().optional(),
      secretEnv: z.string().optional(),
      usernameEnv: z.string().optional(),
    })
    .optional(),
  request: z
    .object({
      method: z.enum(['POST', 'GET']).default('POST'),
      path: z.string().default(''),
      bodyTemplate: z.record(z.string(), z.string()).optional(),
      headers: z.record(z.string(), z.string()).optional(),
      /** Where the verdict lives in the response, and the value that means "matched". */
      matchedFlag: z.object({ path: z.string(), equals: z.unknown().optional() }),
      scorePath: z.string().optional(),
      sourcePath: z.string().optional(),
    })
    .optional(),
});

export type BiometricConfig = z.infer<typeof biometricSchema>;

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
      .prefault({}),
    checkDigit: z
      .object({
        enabled: z.boolean().default(true),
        algorithm: checksumEnum.default('crockford-sha256'),
      })
      .prefault({}),
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

/**
 * Data-protection posture (ORCS §9).
 *
 * The controller is a deployment fact -- one subnational government runs one instance and is
 * the body accountable for what it processes -- so it is declared once rather than passed on
 * every grant. It is optional here and falls back to `credential.issuerName`, which is a
 * defensible default (the body issuing the credential is processing the data to do it) but
 * not always the right one: where an agency issues on behalf of the state, the state is the
 * controller. A deployment SHOULD name it explicitly.
 *
 * `legalBases` are the non-consent bases this jurisdiction relies on. None ship by default:
 * consent is a lawful basis everywhere this vocabulary comes from, and every other basis is
 * somebody's specific statute. Declaring a "public task" entry on a government's behalf would
 * be a guess about their statute book wearing a version number.
 */
const legalBasisSchema = z.object({
  id: z.string().min(1),
  kind: z.enum([
    'consent',
    'contract',
    'legal_obligation',
    'vital_interests',
    'public_task',
    'legitimate_interests',
  ]),
  name: z.string().min(1),
  instrument: z.string().min(1),
  jurisdiction: z.string().min(1),
  controller: z.string().min(1).optional(),
  version: z.string().min(1).default('1.0'),
  effectiveFrom: z.string().min(1),
  effectiveTo: z.string().min(1).optional(),
});

const dataProtectionSchema = z.object({
  /** The accountable body. Falls back to `credential.issuerName`. */
  controller: z.string().min(1).optional(),
  /** A body processing on the controller's behalf, when one does. */
  processor: z.string().min(1).optional(),
  /** Non-consent lawful bases this deployment relies on. */
  legalBases: z.array(legalBasisSchema).default([]),
  /** Basis for grants that name none. Defaults to consent itself. */
  defaultLegalBasisReference: z.string().min(1).optional(),
});

export type LegalBasisConfig = z.infer<typeof legalBasisSchema>;

export const countryConfigSchema = z
  .object({
  countryCode: z.string().length(2),
  countryName: z.string(),
  defaultSubnationalUnit: z.string().optional(),
  foundational: foundationalSchema,
  residency: residencySchema.prefault({}),
  credential: credentialSchema,
  // Country-default Resident ID format; a subnationalUnit may override it. Omit it for the
  // default KT-XXXX-XXXX-C scheme.
  residentId: residentIdSchema.prefault({}),
  // Both default to today's behaviour, so a config that omits them is unchanged.
  wallet: walletSchema.prefault({}),
  presentation: presentationSchema.prefault({}),
  // Sign-in relying parties. Empty by default: a deployment that does not use SSO simply
  // omits this, and no RPs are registered.
  oidc: oidcSchema.prefault({}),
  // An external provider residents may sign in with (this deployment as the RELYING party).
  // Absent by default: nothing here is required to run.
  upstreamOidc: upstreamOidcSchema.optional(),
  // Deployment-wide profiles. Read from the default (first) country config, the same way
  // the presentation profile is. Omit them and you get: shared-key operator auth with a
  // boot warning, no messaging, and no contact directory.
  operatorAuth: operatorAuthSchema.prefault({}),
  messaging: messagingSchema.optional(),
  contactDirectory: contactDirectorySchema.prefault({}),
  // Biometric authority for the AAL3 step-up. Deployment-wide; default NONE (no step-up).
  biometric: biometricSchema.prefault({}),
  // Cross-issuer trust. Deployment-wide, read from the default config. Empty by default:
  // a deployment trusts only its own issuer until it names peers here.
  federation: federationSchema.prefault({}),
  // Who is accountable for the personal data, and under what law (ORCS §9).
  dataProtection: dataProtectionSchema.prefault({}),
  subnationalUnits: z.array(subnationalUnitSchema).default([]),
  })
  .superRefine((v, ctx) => {
    // The Legal Basis Registry is a closed vocabulary (ORCS §9), and the default reference is
    // the one every grant that names nothing else will cite. Catching an unknown id here
    // turns "every consent on this deployment is refused at run time" into a refusal to
    // start, which is the cheaper way to find out.
    const declared = new Set([CONSENT_LEGAL_BASIS_ID, ...v.dataProtection.legalBases.map((b) => b.id)]);
    const fallback = v.dataProtection.defaultLegalBasisReference;
    if (fallback && !declared.has(fallback)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['dataProtection', 'defaultLegalBasisReference'],
        message:
          `dataProtection.defaultLegalBasisReference "${fallback}" is not declared in ` +
          `dataProtection.legalBases, and is not the built-in "${CONSENT_LEGAL_BASIS_ID}". ` +
          'Every legalBasisReference must resolve through the registry (ORCS §9).',
      });
    }
    const seen = new Set<string>();
    for (const b of v.dataProtection.legalBases) {
      if (seen.has(b.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['dataProtection', 'legalBases'],
          message: `duplicate legal basis id "${b.id}"; a replaced basis would silently change the meaning of every consent citing it`,
        });
      }
      seen.add(b.id);
      // Validated here as well as in the registry, so an unreadable date is a config error at
      // load rather than a registry exception thrown out of platform init -- same failure,
      // but one of them names the file and the field.
      for (const field of ['effectiveFrom', 'effectiveTo'] as const) {
        const value = b[field];
        if (value !== undefined && !Number.isFinite(Date.parse(value))) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['dataProtection', 'legalBases'],
            message: `legal basis "${b.id}" has an unparseable ${field} ("${value}")`,
          });
        }
      }
      if (b.id === CONSENT_LEGAL_BASIS_ID) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['dataProtection', 'legalBases'],
          message: `"${CONSENT_LEGAL_BASIS_ID}" is registered by the platform and must not be redeclared`,
        });
      }
    }

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
    assertHumanReviewDeclared(cfg, file);
    map.set(cfg.countryCode.toUpperCase(), cfg);
  }
  return map;
}


/**
 * A jurisdiction that can decide alone must say where a person goes to be heard.
 *
 * Nigeria's NDPA 2023 §37, GDPR Article 22 and Convention 108+ all give a person subject to a
 * solely-automated decision with legal effect the right to obtain HUMAN INTERVENTION, to put
 * their case, and to have it reconsidered by somebody able to reach a different answer. The
 * statutory exceptions -- contract, authorised by law, consent -- permit such decisions being
 * taken; they do not remove that safeguard.
 *
 * Refused at load rather than warned about. There is no safe degraded mode: a deployment that
 * automates residency decisions with nowhere to appeal leaves somebody refused by software with
 * nobody to ask, and that failure stays invisible until it is a person's problem. Same posture
 * as the secrets that refuse to boot rather than fall back to a guessable default.
 *
 * Checked HERE rather than inside the schema, deliberately. The obligation falls on a
 * DEPLOYMENT, and a deployment is what this function builds -- YAML, read from disk, at boot.
 * A test assembling a config object in memory is not one, and putting the rule in the schema
 * made every fixture in the tree carry a compliance declaration on behalf of a jurisdiction
 * that does not exist. The rule is no weaker for sitting at the boundary; it is aimed at the
 * thing it actually governs.
 */
export function assertHumanReviewDeclared(cfg: CountryConfig, source = 'config'): void {
  const automatable = permitsAutomatedDecisions({
    bindingRequired: cfg.residency.applicantBinding.required,
    acceptedBindingMethods: cfg.residency.applicantBinding.acceptedMethods,
    acceptedResidenceMethods: cfg.residency.residence.acceptedMethods,
  });
  if (automatable && !cfg.residency.humanReview) {
    throw new Error(
      `${source}: this jurisdiction accepts methods that permit a residency decision to be ` +
        'taken with no person involved, so residency.humanReview.path MUST declare where an ' +
        'affected person obtains human review (NDPA 2023 s.37, GDPR Art.22, Convention 108+). ' +
        'Either declare it, or require a human method: applicantBinding.acceptedMethods ' +
        '[attended_comparison] with required true, or residence.acceptedMethods ' +
        '[authority_attestation].',
    );
  }
}
