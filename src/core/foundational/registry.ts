import { FoundationalProvider, ProviderConfig } from './types';
import { GenericRestAdapter } from './adapters/generic-rest.adapter';
import { GenericXmlAdapter } from './adapters/generic-xml.adapter';
import { DatasetFileAdapter } from './adapters/dataset-file.adapter';
import { NinAdapter } from './adapters/nin.adapter';
import { AadhaarAdapter } from './adapters/aadhaar.adapter';
import { MockAdapter } from './adapters/mock.adapter';
import { shortHash } from './util';

/** Order-independent JSON so the cache key is identical for equal configs. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k]))
      .join(',') +
    '}'
  );
}

export type ProviderFactory = (pepper?: string) => FoundationalProvider;

/**
 * Maps a provider code (declared in country config) to an adapter factory.
 * Adding a new country almost always means adding a YAML file that points at one of the
 * config-driven sources -- GENERIC_REST (JSON API), GENERIC_XML (XML/SOAP API), or
 * DATASET_FILE / IMPORT (an imported register extract). Only providers with unusual
 * semantics need a new entry here.
 */
const FACTORIES: Record<string, ProviderFactory> = {
  GENERIC_REST: (p) => new GenericRestAdapter('GENERIC_REST', p),
  GENERIC_XML: (p) => new GenericXmlAdapter('GENERIC_XML', p),
  DATASET_FILE: (p) => new DatasetFileAdapter('DATASET_FILE', p),
  IMPORT: (p) => new DatasetFileAdapter('IMPORT', p), // alias for DATASET_FILE
  NG_NIN: (p) => new NinAdapter(p),
  IN_AADHAAR: (p) => new AadhaarAdapter(p),
  MOCK: (p) => new MockAdapter(p),
};

export class ProviderRegistry {
  private cache = new Map<string, FoundationalProvider>();
  constructor(private pepper: string) {}

  register(code: string, factory: ProviderFactory): void {
    FACTORIES[code] = factory;
  }

  /**
   * Build (once) and initialize the provider for this config. The cache is keyed by the
   * full config, not just the provider code: one registry is shared across every
   * jurisdiction, and two deployments can use the same code (GENERIC_REST, GENERIC_XML,
   * DATASET_FILE/IMPORT) with different endpoints, datasets, or mappings. Keying on the code
   * alone would hand the second deployment the first one's adapter.
   */
  resolve(config: ProviderConfig): FoundationalProvider {
    const cacheKey = `${config.code}:${shortHash(stableStringify(config))}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const known = FACTORIES[config.code];
    if (!known) {
      // Unknown code falls back to the config-driven generic adapter so that a typo or a
      // new provider never hard-crashes the platform. But it must not do so silently: a
      // misspelled provider then starts up cleanly and fails at verify time as
      // PROVIDER_UNREACHABLE, which sends whoever debugs it to the network instead of the
      // config.
      console.warn(
        `[foundational] unknown provider code '${config.code}'; falling back to the ` +
          `generic REST adapter. Known codes: ${Object.keys(FACTORIES).join(', ')}`,
      );
    }
    const factory = known ?? ((p?: string) => new GenericRestAdapter(config.code, p));

    const provider = factory(this.pepper);
    provider.init(config);
    this.cache.set(cacheKey, provider);
    return provider;
  }
}
