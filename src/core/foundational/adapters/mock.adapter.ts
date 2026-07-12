import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';
import { tokenizeSubject } from '../util';

/**
 * Deterministic mock foundational provider.
 *
 * Purpose: let a state pilot, a hackathon, or a CI pipeline run the ENTIRE
 * residency + credential + SSO stack end to end with zero dependency on a live,
 * paid national ID API. Any identifier whose primary value ends in an even digit
 * "verifies"; odd fails. This is only ever wired up when config sets
 * `foundational.provider: MOCK`.
 */
export class MockAdapter implements FoundationalProvider {
  readonly code = 'MOCK';
  private pepper: string;
  constructor(pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.pepper = pepper;
  }

  init(_config: ProviderConfig): void {
    /* nothing to initialize */
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const primary = Object.values(input.identifiers)[0] ?? '';
    const lastDigit = Number(primary.replace(/\D/g, '').slice(-1) || '1');
    const ok = lastDigit % 2 === 0;

    if (!ok) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: 'MOCK_NO_MATCH',
      };
    }

    return {
      verified: true,
      providerCode: this.code,
      assuranceLevel: 'verified',
      identity: {
        subjectRef: tokenizeSubject(this.code, primary, this.pepper),
        fullName: (input.identifiers.fullName as string) ?? 'Amina Test Citizen',
        givenName: (input.identifiers.givenName as string) ?? 'Amina',
        familyName: (input.identifiers.familyName as string) ?? 'Test',
        dateOfBirth: (input.identifiers.dateOfBirth as string) ?? '1990-01-01',
        gender: 'F',
        phone: (input.identifiers.phone as string) ?? '+2348000000000',
      },
    };
  }
}
