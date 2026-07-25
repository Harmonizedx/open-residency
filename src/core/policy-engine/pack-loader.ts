import { readFileSync } from 'node:fs';
import { load as loadYaml } from 'js-yaml';
import { z } from 'zod';
import { PolicyPack } from './types';

/**
 * Load and validate a policy pack from YAML.
 *
 * A pack is the natural evolution of a country config YAML -- same file format, same Zod
 * validation discipline. Signature verification (via the existing Signer/KMS) and
 * reject-unsigned-in-production are a later phase; this phase establishes the shape and the
 * structural validation so a malformed pack fails at load rather than mid-decision.
 */

const conditionSchema = z.object({
  path: z.string().min(1),
  op: z.enum(['gte', 'lte', 'gt', 'lt', 'eq', 'neq', 'in', 'exists']),
  value: z.unknown().optional(),
});

const ruleSchema = z.object({
  id: z.string().min(1),
  all: z.array(conditionSchema).optional(),
  any: z.array(conditionSchema).optional(),
  exclusions: z.array(conditionSchema).optional(),
});

const packSchema = z.object({
  metadata: z.object({
    name: z.string().min(1),
    version: z.string().min(1),
    owner: z.string().optional(),
    effectiveFrom: z.string().optional(),
    expiresAt: z.string().optional(),
  }),
  rules: z.record(ruleSchema).default({}),
  floor: z
    .object({
      sealedFields: z.array(z.string()).optional(),
      forbiddenFactPaths: z.record(z.array(z.string())).optional(),
    })
    .optional(),
  overrides: z.record(z.unknown()).optional(),
  config: z.record(z.unknown()).optional(),
});

export function parsePack(raw: unknown): PolicyPack {
  return packSchema.parse(raw) as PolicyPack;
}

export function loadPack(filePath: string): PolicyPack {
  const doc = loadYaml(readFileSync(filePath, 'utf8'));
  return parsePack(doc);
}
