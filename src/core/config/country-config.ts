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

export const countryConfigSchema = z.object({
  countryCode: z.string().length(2),
  countryName: z.string(),
  defaultSubnationalUnit: z.string().optional(),
  foundational: foundationalSchema,
  residency: residencySchema.default({}),
  credential: credentialSchema,
  subnationalUnits: z.array(subnationalUnitSchema).default([]),
});

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
