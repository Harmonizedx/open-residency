import { GenericRestAdapter } from './generic-rest.adapter';
import {
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';

/**
 * Nigeria NIN adapter.
 *
 * NIMC-style verification typically takes a NIN plus a demographic corroborator
 * (date of birth or last name) and returns a verification match with attributes.
 * In practice deployments call a licensed verification gateway rather than NIMC
 * directly, and many of those are ordinary REST endpoints, so this adapter mostly
 * inherits GenericRestAdapter and adds two NIN-specific behaviours:
 *
 *   1. It enforces the NIN format (11 digits) before spending a paid API call.
 *   2. It never lets the raw NIN leave the adapter: only the tokenized subjectRef
 *      and mapped demographic attributes are returned upstream.
 *
 * Set the real gateway endpoint, auth, and response mapping in config/countries/ng.yaml.
 */
export class NinAdapter extends GenericRestAdapter {
  constructor(pepper?: string) {
    super('NG_NIN', pepper);
  }

  init(config: ProviderConfig): void {
    super.init(config);
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const nin = (input.identifiers.nin ?? '').trim();
    if (!/^\d{11}$/.test(nin)) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: 'INVALID_NIN_FORMAT',
      };
    }
    return super.verify(input);
  }
}
