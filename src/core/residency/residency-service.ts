// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
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
import {
  RelationshipAttributes,
  RelationshipStatus,
  TransitionRequest,
  applyTransition,
  isTerminal,
  newRelationship,
  relationshipOf,
} from './lifecycle';
import { AssuranceRegistry } from '../assurance/registry';
import { buildDefaultAssuranceRegistry } from '../assurance/profiles';
import { generateResidentId } from './resident-id';
import { erasureTombstone } from '../privacy/erasure';
import {
  RetentionPolicy,
  RetentionSelection,
  selectResidencyDue,
} from '../privacy/retention';
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

/** Unit codes are short identifiers (KT, NG-NI), never free text. */
const UNIT_CODE_PATTERN = /^[A-Za-z0-9-]{1,32}$/;

/**
 * Check a requested subnational unit, returning a rejection reason or `undefined`.
 *
 * Two independent checks, deliberately not collapsed into one. Membership is the real
 * rule: a jurisdiction declares its units, and you cannot be issued residency of a unit
 * that does not exist. The character-class check is the backstop for a config that
 * declares no units at all (`subnationalUnits` defaults to an empty array), where there is
 * no list to match against but still no reason to accept markup or control characters.
 */
function validateSubnationalUnit(cfg: CountryConfig, unitCode: string): string | undefined {
  if (typeof unitCode !== 'string' || !UNIT_CODE_PATTERN.test(unitCode)) {
    return 'INVALID_SUBNATIONAL_UNIT';
  }
  if (cfg.subnationalUnits.length > 0 && !cfg.subnationalUnits.some((u) => u.code === unitCode)) {
    return 'UNKNOWN_SUBNATIONAL_UNIT';
  }
  return undefined;
}

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
   * Who took the enrolment decision, for ORCS §4.3 decision provenance. An operator id from
   * the authenticated enrolment context; defaults to a generic marker rather than inventing
   * an actor, so a record never names somebody who did not decide it.
   */
  decidedBy?: string;
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
    /**
     * The ORCS §8 registry the recorded assurance value resolves against, so §4.3's
     * `assuranceProfileId` names a governed record rather than repeating the bare word.
     * Defaults to the shipped registry, which is what a deployment that has not customised
     * one is using anyway.
     */
    private assurance: AssuranceRegistry = buildDefaultAssuranceRegistry(),
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
      responseFormat: cfg.foundational.responseFormat,
      xml: cfg.foundational.xml,
      dataset: cfg.foundational.dataset,
      request: cfg.foundational.request,
      responseMapping: cfg.foundational.responseMapping as any,
      verifiedFlag: cfg.foundational.verifiedFlag,
      assuranceOnSuccess: cfg.foundational.assuranceOnSuccess,
      authenticatesApplicant: cfg.foundational.authenticatesApplicant,
      extra: cfg.foundational.extra,
    });
  }

  async issue(cfg: CountryConfig, req: IssueResidencyRequest): Promise<IssueResidencyResult> {
    // 0. Validate the claimed subnational unit before anything else consumes it.
    //
    // This value arrives from the request body and is persisted on the record, asserted
    // into the credential, and rendered in the admin console. Enrolling into a unit the
    // jurisdiction has not declared is meaningless on its own terms, and accepting an
    // arbitrary string here is what turns an unvalidated field into a stored-injection
    // vector for anything downstream that renders it.
    const unitRejection = validateSubnationalUnit(cfg, req.subnationalUnit);
    if (unitRejection) return { status: 'rejected', reason: unitRejection };

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
    //
    // Idempotency is now conditional on the relationship still holding. Returning `exists`
    // for a relationship that was ENDED would hand back a stale record -- original unit,
    // original evidence, original assurance -- to someone re-enrolling precisely because
    // their circumstances changed. A person who left and came back gets a re-evaluation.
    //
    // A SUSPENDED relationship also returns `exists`: it is under adjudication (ORCS §7), and
    // re-enrolling is not the way to resolve that.
    const existing = await this.store.findBySubjectRef(identity.subjectRef);
    const priorRelationship = existing ? relationshipOf(existing) : null;
    if (existing && priorRelationship && !isTerminal(priorRelationship.status)) {
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
    //
    // A returning person keeps their resident id -- they are the same person, and the register
    // holds one record for them -- but takes a FRESH status-list index. The index of the
    // credential issued under the ended relationship keeps its bit, so that credential stays
    // revoked; reusing the index would resurrect a dead credential the moment the new one was
    // issued. Indices are only ever handed out by `nextStatusIndex`, so none is reused.
    const residentId =
      existing?.residentId ?? (await this.generateUniqueResidentId(cfg, req.subnationalUnit));
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

    // 6b. State what this relationship says about itself (ORCS §4.3).
    //
    // Evidence is referenced, not copied: §4.3 asks for references, and duplicating the
    // residence and binding detail here would create a second copy to disagree with the first.
    const evidenceRefs = [
      `binding:${binding.method}${binding.ref ? `:${binding.ref}` : ''}`,
      `residence:${residence.method}:${residence.level}`,
    ];
    const relationship = newRelationship({
      // Purpose is recorded because §4.3 requires it and never read by anything. A deployment
      // holds one kind of relationship, so this states what the register is FOR rather than
      // sorting people into categories that could gate what they reach.
      purpose: cfg.residency.proofOfResidence
        ? 'Subnational residency for service delivery and planning'
        : 'Subnational residency',
      policyVersion: this.policyVersionFor(cfg),
      evidenceRefs,
      assuranceProfileId:
        this.assurance.resolve(result.assuranceLevel, result.providerCode)?.id ?? undefined,
      issuer: cfg.credential.issuerDid,
      decidedBy: req.decidedBy ?? 'enrolment',
      at: issued.issuedAt,
    });

    const record: ResidentRecord = {
      // A returning person keeps their row: `subjectRef` is unique, so this is an update of
      // the same record with a new relationship on it, not a second residency.
      id: existing?.id ?? crypto.randomUUID(),
      residentId,
      subjectRef: identity.subjectRef,
      countryCode: cfg.countryCode,
      subnationalUnit: req.subnationalUnit,
      providerCode: result.providerCode,
      assuranceLevel: result.assuranceLevel,
      binding,
      residence: residenceClaim,
      provisional,
      relationship,
      credentialId: issued.credentialId,
      statusListIndex,
      createdAt: issued.issuedAt,
      person: claims.person,
    };
    await this.store.save(record);

    return { status: 'issued', residentId, credentialJwt: issued.jwt, record };
  }

  /**
   * Mint a resident id in the jurisdiction's configured format, retrying on the (rare)
   * chance of a collision. The store's `residentId` is unique, so this closes the gap a
   * low-entropy custom format could otherwise open.
   */
  private async generateUniqueResidentId(cfg: CountryConfig, unitCode: string): Promise<string> {
    // The unit's own format wins; absent one, it inherits the country default.
    const unit = cfg.subnationalUnits.find((u) => u.code === unitCode);
    const format = unit?.residentId ?? cfg.residentId;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = generateResidentId(unitCode, format, cfg.countryCode);
      if (!(await this.store.findByResidentId(id))) return id;
    }
    throw new Error(
      'exhausted attempts generating a unique resident id; increase residentId entropy in config',
    );
  }

  /**
   * A reproducible identifier for the ruleset a decision was taken under (ORCS §4.3).
   *
   * Derived by hashing the rules that actually decide an issuance -- the residency policy, the
   * residence policy and the assurance the foundational check confers. A content hash is
   * honest about what it is: it changes exactly when the rules change, and two deployments on
   * the same rules produce the same value. It is NOT a signed policy version; ORCS §4.6 wants
   * policies signed, versioned and effective-dated, which is finding G-13 and not built. When
   * that lands, this becomes a lookup rather than a hash.
   */
  private policyVersionFor(cfg: CountryConfig): string {
    const material = JSON.stringify({
      residency: cfg.residency,
      assuranceOnSuccess: cfg.foundational.assuranceOnSuccess,
    });
    return `sha256:${createHash('sha256').update(material).digest('hex').slice(0, 16)}`;
  }

  /**
   * Move a residency relationship to another state (ORCS §6.2).
   *
   * This is how a jurisdiction records that somebody left, which revoking a credential has
   * never been able to say. The two acts stay separate: this states something about a
   * person's relationship to the jurisdiction, `revoke()` states something about a key. A
   * caller ending a residency will usually want both, and doing both is the caller's decision
   * rather than a side effect hidden in here -- collapsing them is exactly the conflation
   * ADR-0007 exists to undo.
   *
   * Returns a reason string on refusal rather than throwing, matching `issue()`.
   */
  async transitionRelationship(
    residentId: string,
    req: TransitionRequest,
  ): Promise<
    | { ok: true; record: ResidentRecord; from: RelationshipStatus; to: RelationshipStatus }
    | { ok: false; reason: string }
  > {
    const record = await this.store.findByResidentId(residentId);
    if (!record) return { ok: false, reason: 'UNKNOWN_RESIDENT' };

    const current = relationshipOf(record);
    const outcome = applyTransition(current, req);
    if (!outcome.ok) return outcome;

    const updated: ResidentRecord = { ...record, relationship: outcome.attributes };
    await this.store.save(updated);
    return { ok: true, record: updated, from: current.status, to: outcome.attributes.status };
  }

  /** The relationship attributes for a resident, with the pre-lifecycle backfill applied. */
  async relationshipFor(residentId: string): Promise<RelationshipAttributes | null> {
    const record = await this.store.findByResidentId(residentId);
    return record ? relationshipOf(record) : null;
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

  /**
   * Erase a resident's personal data (DPG indicator 7, ORCS §14).
   *
   * Revocation happens FIRST and the order is load-bearing. Erasing the record before
   * revoking would leave a credential in the citizen's wallet that still verifies, against a
   * register that no longer knows who it belongs to -- a credential nobody can revoke because
   * nobody can identify it. Revoke, then erase, and the outstanding credential is dead before
   * its subject becomes unidentifiable.
   *
   * Idempotent: erasing an already-erased resident is a no-op that reports success, so a
   * retried request or a re-run sweep cannot fail halfway and leave a caller unsure.
   */
  async erase(
    cfg: CountryConfig,
    residentId: string,
    at: Date = new Date(),
  ): Promise<{ status: 'erased' | 'already-erased' | 'unknown'; record?: ResidentRecord }> {
    const record = await this.store.findByResidentId(residentId);
    if (!record) return { status: 'unknown' };
    if (record.erasedAt) return { status: 'already-erased', record };

    await this.revoke(cfg, residentId);
    const erased = await this.store.erase(residentId, erasureTombstone(), at);
    return { status: 'erased', record: erased ?? undefined };
  }

  /**
   * Find every residency record past its retention period.
   *
   * Selection only — nothing is destroyed here. The caller decides whether to act, which is
   * what makes a dry run possible: an operator can see exactly which records a sweep would
   * erase before any of them are gone, and a bulk irreversible operation should never be
   * something you discover the scope of afterwards.
   */
  async selectDueForRetention(
    cfg: CountryConfig,
    now: Date = new Date(),
  ): Promise<RetentionSelection<ResidentRecord>> {
    const policy: RetentionPolicy = {
      residencyDays: cfg.residency.retention.residencyDays,
      legalHold: cfg.residency.retention.legalHold,
    };
    // Cheap exits before paging the register: a held or unset policy selects nothing, and
    // reading every row to discover that would be wasteful on a large deployment.
    if (policy.legalHold) return { due: [], skipped: 'legal-hold' };
    if (policy.residencyDays === null) return { due: [], skipped: 'no-policy' };

    const all: ResidentRecord[] = [];
    let offset = 0;
    for (;;) {
      const page = await this.store.list({ countryCode: cfg.countryCode, limit: 500, offset });
      all.push(...page.items);
      offset += page.items.length;
      if (page.items.length === 0 || offset >= page.total) break;
    }
    return selectResidencyDue(all, policy, now);
  }
}
