import { CountryConfig } from '../config/country-config';
import { ProviderRegistry } from '../foundational/registry';
import {
  AssuranceLevel,
  FoundationalProvider,
  FoundationalVerificationInput,
} from '../foundational/types';
import {
  VcIssuer,
  ResidencyClaims,
  IssueOptions,
  buildCredentialBody,
} from '../credentials/vc-issuer';
import { LdpIssuer, LdpCredential, RESIDENCY_LDP_CONTEXT } from '../credentials/ldp-issuer';
import { ResidencyStore, ResidentRecord } from './ports';
import { generateResidentId } from './resident-id';
import { ApplicantBinding, bindingSatisfies, strongestBinding } from '../proofing/binding';
import {
  DEFAULT_RESIDENCE_POLICY,
  ResidenceEvidence,
  ResidencePolicy,
  evaluateResidence,
  reconcileUnit,
} from '../proofing/residence';

/** The credential formats this issuer can produce. */
export type CredentialFormat = 'jwt_vc_json' | 'ldp_vc';

export interface MintedCredential {
  format: CredentialFormat;
  /** A compact JWT string for jwt_vc_json; a JSON-LD object for ldp_vc. */
  credential: string | LdpCredential;
  credentialId: string;
  expiresAt: string;
}

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
  /**
   * Residence evidence the enrolment channel gathered: a ward attestation, an uploaded
   * document, a geospatial match. Combined with any residence locality the foundational
   * provider returned (when the policy opts in), reconciled to the claimed unit, and held
   * to this jurisdiction's proof-of-residence policy. Must originate from a trusted
   * enrolment context -- a caller cannot self-assert that they reside somewhere.
   */
  residenceEvidence?: ResidenceEvidence[];
  /**
   * Binding the enrolment channel performed itself: an agent's in-person comparison, a
   * face/fingerprint match, or an external eID authentication. Combined with any binding
   * the foundational provider attested; the strongest wins. Must originate from a trusted
   * enrolment context, not from an unauthenticated caller asserting its own binding.
   */
  binding?: ApplicantBinding;
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
    /** Present when the deployment also issues JSON-LD credentials (OpenID4VCI / wallets). */
    private ldpIssuer?: LdpIssuer,
  ) {}

  /** The issuance parameters for a country, given an already-reserved status index. */
  private issueOptionsFor(
    cfg: CountryConfig,
    statusListIndex: number,
    context: string[] = cfg.credential.context,
  ): IssueOptions {
    return {
      issuerDid: cfg.credential.issuerDid,
      issuerName: cfg.credential.issuerName,
      type: cfg.credential.type,
      context,
      validityDays: cfg.credential.validityDays,
      statusListIndex,
      statusListUrl: this.statusListUrlFor(cfg),
    };
  }

  /** Rebuild the credential claims for a resident already in the register. */
  claimsForRecord(cfg: CountryConfig, record: ResidentRecord, holderId: string): ResidencyClaims {
    const unit = cfg.subnationalUnits.find((u) => u.code === record.subnationalUnit);
    return {
      holderId,
      residentId: record.residentId,
      subnationalUnit: {
        country: record.countryCode,
        code: record.subnationalUnit,
        name: unit?.name ?? record.subnationalUnit,
        level: unit?.level ?? 'state',
      },
      foundational: {
        provider: record.providerCode,
        assuranceLevel: record.assuranceLevel,
        subjectRef: record.subjectRef,
      },
      applicantBinding: record.binding,
      person: record.person,
      proofOfResidence: cfg.residency.proofOfResidence,
      residence: record.residence,
      provisional: record.provisional,
    };
  }

  /** The proof-of-residence policy for a country, defaulted when the config omits one. */
  private residencePolicyFor(cfg: CountryConfig): ResidencePolicy {
    const p = cfg.residency.residence;
    if (!p) return DEFAULT_RESIDENCE_POLICY;
    return {
      required: p.required,
      targetLevel: p.targetLevel,
      acceptedMethods: p.acceptedMethods,
      unitMatchRequired: p.unitMatchRequired,
      recencyDays: p.recencyDays,
      methodCeiling: p.methodCeiling,
      acceptFoundationalResidence: p.acceptFoundationalResidence,
    };
  }

  /**
   * Issue a credential for an existing resident, bound to a key the holder controls.
   *
   * This is the OpenID4VCI path. Enrollment (the foundational ID check) already happened
   * and produced a ResidentRecord; here the citizen's wallet has proved possession of a
   * key, and we mint a credential whose `credentialSubject.id` is that wallet's DID.
   *
   * The record's existing `statusListIndex` is reused rather than a fresh one reserved.
   * That matters: it means every credential ever issued to a resident -- in either
   * format, to any number of wallets -- shares one revocation bit. Revoking the resident
   * revokes all of them at once. Allocating a new index here would silently leave older
   * credentials live after a revocation.
   */
  async mintForHolder(
    cfg: CountryConfig,
    record: ResidentRecord,
    holderId: string,
    format: CredentialFormat,
  ): Promise<MintedCredential> {
    const claims = this.claimsForRecord(cfg, record, holderId);

    if (format === 'jwt_vc_json') {
      const issued = await this.issuer.issue(
        claims,
        this.issueOptionsFor(cfg, record.statusListIndex),
      );
      return {
        format,
        credential: issued.jwt,
        credentialId: issued.credentialId,
        expiresAt: issued.expiresAt,
      };
    }

    if (!this.ldpIssuer) {
      throw new Error('this deployment is not configured to issue ldp_vc credentials');
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + cfg.credential.validityDays * 86400_000);
    const credentialId = `urn:uuid:${crypto.randomUUID()}`;

    // JSON-LD credentials must declare the residency context, or canonicalization would
    // drop our custom claims from the signed form. The document loader is pinned and
    // offline, so this is a local lookup, not a fetch.
    const body = buildCredentialBody(
      claims,
      this.issueOptionsFor(cfg, record.statusListIndex, RESIDENCY_LDP_CONTEXT),
      { credentialId, issuedAt: now, expiresAt },
    );
    const signed = await this.ldpIssuer.sign(body, cfg.credential.issuerDid);

    return {
      format,
      credential: signed,
      credentialId,
      expiresAt: expiresAt.toISOString(),
    };
  }

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
      authenticatesApplicant: cfg.foundational.authenticatesApplicant,
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

    // 3. Establish applicant -> identity binding.
    //
    // A passed foundational check means the identity RECORD is genuine. It does NOT, on
    // its own, mean the applicant OWNS it -- a lookup anyone with the number could pass is
    // not owner proof. Combine any binding the provider attested (an OTP to the registered
    // device, an eID redirect) with any the enrolment channel performed (an agent's
    // in-person comparison, a face/fingerprint match), take the strongest, and hold it to
    // this jurisdiction's policy before issuing anything.
    const binding = strongestBinding(result.applicantBinding, req.binding);
    const bindingPolicy = cfg.residency.applicantBinding;
    if (bindingPolicy.required && !bindingSatisfies(binding, bindingPolicy.acceptedMethods)) {
      return {
        status: 'rejected',
        reason: `APPLICANT_BINDING_REQUIRED_${binding.method.toUpperCase()}`,
      };
    }

    const identity = result.identity!;

    // 4. One person per (provider subject) per deployment: idempotent issuance.
    const existing = await this.store.findBySubjectRef(identity.subjectRef);
    if (existing) {
      return { status: 'exists', residentId: existing.residentId, record: existing };
    }

    // 4b. Establish proof of residence.
    //
    // A genuine, owner-bound identity still does not establish that the person RESIDES in
    // the unit they are claiming. Gather residence evidence -- the locality the provider
    // returned (never the origin field), plus anything the trusted enrolment channel
    // supplied -- reconcile each to the claimed unit, and hold the result to policy. The
    // provider's residence field is capped low because it is usually self-declared and
    // stale; origin is never eligible.
    const residencePolicy = this.residencePolicyFor(cfg);
    const residenceEvidence: ResidenceEvidence[] = [];
    if (residencePolicy.acceptFoundationalResidence && identity.residenceAdminUnit) {
      residenceEvidence.push({
        method: 'register_declared_residence',
        reportedUnit: identity.residenceAdminUnit,
        adminUnit: reconcileUnit(cfg.subnationalUnits, identity.residenceAdminUnit),
        // Foundational records rarely carry an as-of date; leaving it undated keeps the
        // evidence capped by the recency rule rather than silently trusted as fresh.
      });
    }
    for (const ev of req.residenceEvidence ?? []) {
      residenceEvidence.push({
        ...ev,
        adminUnit: ev.adminUnit ?? reconcileUnit(cfg.subnationalUnits, ev.reportedUnit),
      });
    }
    const residence = evaluateResidence(
      residencePolicy,
      residenceEvidence,
      req.subnationalUnit,
      new Date().toISOString(),
    );
    if (residencePolicy.required && !residence.satisfied) {
      return { status: 'rejected', reason: residence.reason ?? 'PROOF_OF_RESIDENCE_REQUIRED' };
    }
    const residenceClaim: {
      assuranceLevel: typeof residence.level;
      method: typeof residence.method;
      unit?: string;
      asOf?: string;
    } = { assuranceLevel: residence.level, method: residence.method };
    if (residence.unit) residenceClaim.unit = residence.unit;
    if (residence.asOf) residenceClaim.asOf = residence.asOf;

    // 5. Mint residency id + assign a revocation status index.
    const residentId = generateResidentId(req.subnationalUnit);
    const statusListIndex = await this.store.nextStatusIndex(cfg.countryCode);
    const unit = cfg.subnationalUnits.find((u) => u.code === req.subnationalUnit);

    const holderId = req.holderId ?? `urn:resident:${residentId}`;
    const provisional =
      cfg.residency.allowProvisional && req.context?.offline === true ? true : false;

    // 5b. Assemble the credential claims, including the achieved binding.
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
      applicantBinding: binding,
      person: {
        fullName: identity.fullName,
        givenName: identity.givenName,
        familyName: identity.familyName,
        dateOfBirth: identity.dateOfBirth,
        gender: identity.gender,
      },
      proofOfResidence: req.proofOfResidence ?? cfg.residency.proofOfResidence,
      residence: residenceClaim,
      provisional,
    };

    // 6. Issue the Verifiable Credential.
    const issued = await this.issuer.issue(claims, this.issueOptionsFor(cfg, statusListIndex));

    const record: ResidentRecord = {
      id: crypto.randomUUID(),
      residentId,
      subjectRef: identity.subjectRef,
      countryCode: cfg.countryCode,
      subnationalUnit: req.subnationalUnit,
      providerCode: result.providerCode,
      assuranceLevel: result.assuranceLevel,
      binding,
      residence: residenceClaim,
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
