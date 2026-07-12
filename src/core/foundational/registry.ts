import { FoundationalProvider, ProviderConfig } from './types';
import { GenericRestAdapter } from './adapters/generic-rest.adapter';
import { NinAdapter } from './adapters/nin.adapter';
import { AadhaarAdapter } from './adapters/aadhaar.adapter';
import { MockAdapter } from './adapters/mock.adapter';

export type ProviderFactory = (pepper?: string) => FoundationalProvider;

/**
 * Maps a provider code (declared in country config) to an adapter factory.
 * Adding a new country almost always means adding a YAML file that points at
 * GENERIC_REST. Only providers with unusual semantics need a new entry here.
 */
const FACTORIES: Record<string, ProviderFactory> = {
  GENERIC_REST: (p) => new GenericRestAdapter('GENERIC_REST', p),
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

  /** Build (once) and initialize the provider named by config.code. */
  resolve(config: ProviderConfig): FoundationalProvider {
    const cached = this.cache.get(config.code);
    if (cached) return cached;

    const factory =
      FACTORIES[config.code] ??
      // Unknown code falls back to the config-driven generic adapter so that a
      // typo or a new provider never hard-crashes the platform.
      ((p?: string) => new GenericRestAdapter(config.code, p));

    const provider = factory(this.pepper);
    provider.init(config);
    this.cache.set(config.code, provider);
    return provider;
  }
}
