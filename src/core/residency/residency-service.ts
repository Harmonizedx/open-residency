import { CountryConfig } from '../config/country-config';
import { ProviderRegistry } from '../foundational/registry';
import {
  AssuranceLevel,
  FoundationalProvider,
  FoundationalVerificationInput,
} from '../foundational/types';
import { VcIssuer, ResidencyClaims } from '../credentials/vc-issuer';
import { ResidencyStore, ResidentRecord } from './ports';
import { generateResidentId } from './resident-id';

const ASSURANCE_RANK: Record<AssuranceLevel, number> = {
  none: 0,
  basic: 1,
  verified: 2,
  high: 3,
};

export interface IssueResidencyRequest {
  countryCode: string;
  subnationalUnit: string; // unit code, e.g. KT
  identifiers: Record<string, string>;
  challengeRef?: string;
  /** did:key the holder controls; falls back to a urn if omitted (custodial wallet). */
  holderId?: string;
  proofOfResidence?: string; // overrides config default when an operator attests
  context?: Record<string, unknown>;
}

export type IssueResidencyResult =
  | { status: 'issued'; residentId: string; credentialJwt: string; record: ResidentRecord }
  | { status: 'exists'; residentId: string; record: ResidentRecord }
  | { status: 'challenge'; challenge: { type: string; channel: string; challengeRef: string } }
  | { status: 'rejected'; reason: string };

/**
 * The orchestration that ties the four layers together. It is deliberately free of
 * any web framework so it can be unit-tested and embedded anywhere.
 */
export class ResidencyService {
  constructor(
    private registry: ProviderRegistry,
    private issuer: VcIssuer,
    private store: ResidencyStore,
    private statusListUrlFor: (cfg: CountryConfig) => string,
  ) {}

  /** Resolve the foundational provider for a country from its config. */
  getProvider(cfg: CountryConfig): FoundationalProvider {
    return this.registry.resolve({
      code: cfg.foundational.provider,
      baseUrl: cfg.foundational.baseUrl,
      auth: cfg.foundational.auth,
      timeoutMs: cfg.foundational.timeoutMs,
      request: cfg.foundational.request,
      responseMapping: cfg.foundational.responseMapping as any,
      verifiedFlag: cfg.foundational.verifiedFlag,
      assuranceOnSuccess: cfg.foundational.assuranceOnSuccess,
      extra: cfg.foundational.extra,
    });
  }

  async issue(cfg: CountryConfig, req: IssueResidencyRequest): Promise<IssueResidencyResult> {
    // 1. Resolve the foundational provider from country config and verify.
    const provider = this.getProvider(cfg);

    const input: FoundationalVerificationInput = {
      countryCode: cfg.countryCode,
      identifiers: req.identifiers,
      challengeRef: req.challengeRef,
      context: req.context,
    };

    const result = await provider.verify(input);

    if (!result.verified) {
      if (result.pendingChallenge) {
        return { status: 'challenge', challenge: result.pendingChallenge };
      }
      return { status: 'rejected', reason: result.reason ?? 'FOUNDATIONAL_REJECTED' };
    }

    // 2. Enforce assurance policy.
    const required = cfg.residency.minAssurance;
    if (ASSURANCE_RANK[result.assuranceLevel] < ASSURANCE_RANK[required]) {
      return { status: 'rejected', reason: `ASSURANCE_TOO_LOW_${result.assuranceLevel}` };
    }

    const identity = result.identity!;

    // 3. One person per (provider subject) per deployment: idempotent issuance.
    const existing = await this.store.findBySubjectRef(identity.subjectRef);
    if (existing) {
      return { status: 'exists', residentId: existing.residentId, record: existing };
    }

    // 4. Mint residency id + assign a revocation status index.
    const residentId = generateResidentId(req.subnationalUnit);
    const statusListIndex = await this.store.nextStatusIndex(cfg.countryCode);
    const unit = cfg.subnationalUnits.find((u) => u.code === req.subnationalUnit);

    const holderId = req.holderId ?? `urn:resident:${residentId}`;
    const provisional =
      cfg.residency.allowProvisional && req.context?.offline === true ? true : false;

    // 5. Issue the Verifiable Credential.
    const claims: ResidencyClaims = {
      holderId,
      residentId,
      subnationalUnit: {
        country: cfg.countryCode,
        code: req.subnationalUnit,
        name: unit?.name ?? req.subnationalUnit,
        level: unit?.level ?? 'state',
      },
      foundational: {
        provider: result.providerCode,
        assuranceLevel: result.assuranceLevel,
        subjectRef: identity.subjectRef,
      },
      person: {
        fullName: identity.fullName,
        givenName: identity.givenName,
        familyName: identity.familyName,
        dateOfBirth: identity.dateOfBirth,
        gender: identity.gender,
      },
      proofOfResidence: req.proofOfResidence ?? cfg.residency.proofOfResidence,
      provisional,
    };

    const issued = await this.issuer.issue(claims, {
      issuerDid: cfg.credential.issuerDid,
      issuerName: cfg.credential.issuerName,
      type: cfg.credential.type,
      context: cfg.credential.context,
      validityDays: cfg.credential.validityDays,
      statusListIndex,
      statusListUrl: this.statusListUrlFor(cfg),
    });

    const record: ResidentRecord = {
      id: crypto.randomUUID(),
      residentId,
      subjectRef: identity.subjectRef,
      countryCode: cfg.countryCode,
      subnationalUnit: req.subnationalUnit,
      providerCode: result.providerCode,
      assuranceLevel: result.assuranceLevel,
      provisional,
      credentialId: issued.credentialId,
      statusListIndex,
      createdAt: issued.issuedAt,
      person: claims.person,
    };
    await this.store.save(record);

    return { status: 'issued', residentId, credentialJwt: issued.jwt, record };
  }

  /** Revoke a residency credential by flipping its status-list bit. */
  async revoke(cfg: CountryConfig, residentId: string): Promise<boolean> {
    const record = await this.store.findByResidentId(residentId);
    if (!record) return false;
    const list = await this.store.loadStatusList(cfg.countryCode);
    list.set(record.statusListIndex, true);
    await this.store.saveStatusList(cfg.countryCode, list);
    return true;
  }
}
