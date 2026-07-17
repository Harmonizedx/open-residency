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
  private authenticatesApplicant = false;
  constructor(pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.authenticatesApplicant = config.authenticatesApplicant === true;
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
      // Honour the same binding contract as real adapters: a mock "authenticatesApplicant"
      // config simulates an owner-authenticating source; otherwise the mock is a bare
      // lookup and attests no binding.
      applicantBinding: this.authenticatesApplicant
        ? {
            method: 'authoritative_authentication',
            ref: input.challengeRef,
            verifiedAt: new Date().toISOString(),
          }
        : undefined,
      identity: {
        subjectRef: tokenizeSubject(this.code, primary, this.pepper),
        fullName: (input.identifiers.fullName as string) ?? 'Amina Test Citizen',
        givenName: (input.identifiers.givenName as string) ?? 'Amina',
        familyName: (input.identifiers.familyName as string) ?? 'Test',
        dateOfBirth: (input.identifiers.dateOfBirth as string) ?? '1990-01-01',
        gender: 'F',
        phone: (input.identifiers.phone as string) ?? '+2348000000000',
        // Simulate a record that carries residence AND origin, so the demo can prove the
        // engine uses only residence and never origin as proof-of-residence evidence.
        residenceAdminUnit: (input.identifiers.residenceUnit as string) ?? undefined,
        originAdminUnit: (input.identifiers.originUnit as string) ?? undefined,
      },
    };
  }
}
