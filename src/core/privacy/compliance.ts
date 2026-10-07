// SPDX-License-Identifier: Apache-2.0

/**
 * What a data-protection regulator asks a register to produce, produced from what the
 * register already knows about itself.
 *
 * ## Why this exists
 *
 * A government agency running this software is a data controller under its country's
 * data-protection law, and that law asks for the same things everywhere in substance: a record
 * of processing activities, an impact assessment before high-risk processing, a named officer,
 * a registration with the authority, and breach notification within a fixed number of hours.
 * Most of what those filings contain is a description of the system, and the system can
 * describe itself: which categories of personal data it holds and which it deliberately does
 * not, which processing activities it performs, who the recipients are, what the retention
 * configuration says, whether biometrics or automated decisions are in play, whether modes for
 * vulnerable data subjects are admitted. This module produces that description from the live
 * configuration, so the officer starts from the facts rather than a blank template, and so the
 * description cannot drift from the deployment the way a document does.
 *
 * ## What this deliberately does NOT do
 *
 * It does not produce a filing. What comes out is the factual skeleton of one, labelled as
 * such, with every field the software cannot know marked for the deployment to complete.
 *
 * It does not know any country's law. The authority's name, the grounds on which an
 * assessment is required, the article citations, the retention rule and the breach clock come
 * from a regulatory profile shipped as data (`config/privacy/<CC>.json`); the core evaluates
 * generic conditions -- always, biometrics configured, vulnerable subjects, automated decisions
 * permitted, new technology -- and quotes the profile. A country with no profile gets neutral
 * wording and a 72-hour clock. This keeps the core free of jurisdiction-specific knowledge,
 * which the acceptance suite asserts.
 */

import type { CountryConfig } from '../config/country-config';
import { permitsAutomatedDecisions } from '../residency/decision-mode';

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export type DpiaTriggerCondition = 'always' | 'biometrics' | 'vulnerable' | 'automated' | 'new_technology';

/** A country's data-protection rules as the generators need them. Data, not code. */
export interface RegulatoryProfile {
  authority: string;
  law: string;
  controllerOfMajorImportance?: string;
  dpiaTriggers: Array<{ when: DpiaTriggerCondition; ground: string; because: string }>;
  retentionLapseWhereUnset: string;
  thirdPartySharing?: string;
  breachNotificationHours: number;
  breachSubjectNotification?: string;
  hostingNote?: string;
}

/** Neutral wording for a country with no profile. */
export const NEUTRAL_PROFILE: RegulatoryProfile = {
  authority: 'the supervisory authority',
  law: 'the applicable data-protection law',
  dpiaTriggers: [
    { when: 'always', ground: 'processing of the general public\u2019s personal data under a legal instrument', because: 'a residents\u2019 registration law is such an instrument' },
    { when: 'biometrics', ground: 'sensitive data, including biometrics', because: 'a biometric provider is configured' },
    { when: 'vulnerable', ground: 'vulnerable data subjects', because: 'a register of residents reaches children, the displaced and people without digital access' },
    { when: 'automated', ground: 'decisions by automated means with significant effects', because: 'the accepted methods permit an issuance decision with no person in the loop' },
    { when: 'new_technology', ground: 'new technology for processing', because: 'verifiable credentials, offline verification and federated sign-in are new to most registers' },
  ],
  retentionLapseWhereUnset: 'no statutory period is configured; set residency.retention.residencyDays or document the period relied on',
  breachNotificationHours: 72,
};

/** Read `<dir>/<CC>.json`; undefined when none ships; throws on a malformed file. */
export function loadRegulatoryProfile(dir: string, countryCode: string): RegulatoryProfile | undefined {
  const cc = countryCode.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return undefined;
  const file = join(dir, `${cc}.json`);
  if (!existsSync(file)) return undefined;
  const raw = JSON.parse(readFileSync(file, 'utf8')) as Partial<RegulatoryProfile>;
  if (!raw || typeof raw.authority !== 'string' || !Array.isArray(raw.dpiaTriggers) || typeof raw.breachNotificationHours !== 'number') {
    throw new Error(`${file}: expected a regulatory profile with authority, dpiaTriggers and breachNotificationHours`);
  }
  return { ...NEUTRAL_PROFILE, ...raw } as RegulatoryProfile;
}

export type SupervisoryTier = 'standard' | 'extra_high' | 'ultra_high';

export interface ProcessingActivity {
  id: string;
  purpose: string;
  /** Legal-basis identifiers from the deployment's registry, or `consent`. */
  legalBasisRefs: string[];
  dataSubjects: string[];
  personalData: string[];
  /** What the activity is designed never to hold. Stated, because the regulator will ask. */
  notHeld: string[];
  recipients: string[];
  /** The configured retention, or the statement that none is set and what that means. */
  retention: string;
  security: string[];
  /** Fields the software cannot know and the deployment must complete. */
  toComplete: string[];
}

export interface RecordOfProcessing {
  generatedAt: string;
  /** Labelled so no one mistakes it for the filing. */
  status: 'factual skeleton generated from the live configuration; not a filing';
  controller: string;
  processor?: string;
  jurisdiction: string;
  /** From the regulatory profile, or neutral wording when none ships. */
  law: string;
  supervisoryAuthority: string;
  dataProtectionOfficer?: { name?: string; email?: string; phone?: string };
  supervisoryRegistration?: { authority?: string; registrationNumber?: string; tier?: SupervisoryTier };
  legalBases: Array<{ id: string; kind: string; instrument: string }>;
  activities: ProcessingActivity[];
  toComplete: string[];
}

export interface DpiaTrigger {
  /** The article relied on, where the research confirmed it; otherwise the Directive's own words. */
  ground: string;
  applies: boolean;
  because: string;
}

export interface DpiaFacts {
  generatedAt: string;
  status: 'factual skeleton generated from the live configuration; not an assessment';
  controller: string;
  jurisdiction: string;
  law: string;
  supervisoryAuthority: string;
  triggers: DpiaTrigger[];
  processing: {
    purposes: string[];
    categoriesOfDataSubject: string[];
    categoriesOfPersonalData: string[];
    specialCategoryData: string[];
    recipients: string[];
    retention: string;
    automatedDecisionsPermitted: boolean;
    humanReviewPath?: string;
    residenceAnchor: 'unit' | 'address';
    vulnerableSubjectModesAdmitted: string[];
    selfServiceFactors: string[];
  };
  mitigationsInSoftware: string[];
  toComplete: string[];
}

const PERSONAL_DATA_RESIDENT = [
  'tokenised foundational reference (keyed hash of the national identifier; the identifier itself is never stored)',
  'resident identifier',
  'full name, given name, family name, date of birth, gender (as returned by the foundational source)',
  'subnational unit of residence; residence assurance level, method, date, and the rule inputs (since, mode, attester kind, intent)',
  'applicant-binding method and reference',
  'credential identifier, status and status-list index',
  'phone number as a one-way hash; ciphertext only under contactDirectory.mode: encrypted',
];

const NOT_HELD = [
  'the national identification number in clear',
  'origin, indigeneity, ethnicity, religion or ancestry, in any field (ADR-0015)',
  'a photograph or biometric template returned by a source (dropped, never persisted)',
  'the residential address, unless the jurisdiction anchors residency on addresses (ADR-0011)',
];

function retentionText(cfg: CountryConfig, profile: RegulatoryProfile): string {
  const r = cfg.residency.retention;
  if (r.legalHold) return 'legal hold in force: all retention deletion suspended';
  if (r.residencyDays == null) {
    return `no automatic expiry is configured. The software ships no default on purpose; ${profile.retentionLapseWhereUnset}`;
  }
  return `residency records expire ${r.residencyDays} days after issuance unless a legal hold is set`;
}

/** The record of processing activities, as far as the configuration can state it. */
export function recordOfProcessing(
  cfg: CountryConfig,
  profile: RegulatoryProfile = NEUTRAL_PROFILE,
  nowIso = new Date().toISOString(),
): RecordOfProcessing {
  const controller = cfg.dataProtection.controller ?? cfg.credential.issuerName;
  const rps = cfg.oidc.relyingParties.map((rp) => `${rp.name ?? rp.clientId} (${rp.sector}; client ${rp.clientId})`);
  const peers = cfg.federation.trustedIssuers.map((p) => p.name ?? p.did);
  const bases = cfg.dataProtection.legalBases.map((b) => ({ id: b.id, kind: b.kind, instrument: b.instrument }));
  const baseRefs = bases.map((b) => b.id);
  const retention = retentionText(cfg, profile);
  const security = [
    'keyed-hash tokenisation of the national identifier',
    'issuer keys in HSM/KMS custody with no exportable private key',
    'hash-chained, checkpointed, redactable audit log of every operator action and record read',
    'pairwise sign-in identifiers per relying party',
    'per-operator identity, roles and keys; in-application rate limiting',
    'encryption in transit; contact ciphertext under a key outside the database where kept',
  ];
  const activities: ProcessingActivity[] = [
    {
      id: 'enrolment-and-issuance',
      purpose: cfg.residency.proofOfResidence
        ? 'Establish and evidence a person’s residency in the jurisdiction and issue a credential of it, for service delivery and planning'
        : 'Establish and evidence a person’s residency in the jurisdiction and issue a credential of it',
      legalBasisRefs: baseRefs.length ? baseRefs : ['to be declared: the state’s registration law'],
      dataSubjects: ['residents and applicants for residency', ...(cfg.residency.residence?.modes?.noFixedAbode?.allowed ? ['persons with no fixed abode, including in displacement or host communities'] : [])],
      personalData: PERSONAL_DATA_RESIDENT,
      notHeld: NOT_HELD,
      recipients: ['the resident, as a credential', 'the foundational identity authority, as a verification request (identifier and date of birth)'],
      retention,
      security,
      toComplete: ['the lawful basis for the foundational-identity check, agreed with the identity authority', 'whether the identity authority is a joint controller'],
    },
    {
      id: 'consent-management',
      purpose: 'Record, evidence and enforce the resident’s permission for a relying party to receive claims',
      legalBasisRefs: ['consent', ...baseRefs],
      dataSubjects: ['residents'],
      personalData: ['resident identifier', 'relying party, purpose, data categories, scopes', 'grant, expiry and withdrawal timestamps; evidence of agreement; signed receipt'],
      notHeld: ['the claims themselves'],
      recipients: ['the resident (signed receipt)', 'auditors'],
      retention: 'consent records are kept for evidence; withdrawal stops processing and does not shorten the record’s life',
      security,
      toComplete: ['the retention period for consent evidence'],
    },
    {
      id: 'federated-sign-in',
      purpose: 'Authenticate a resident to a sector service with a pairwise identifier and only the claims consented to',
      legalBasisRefs: ['consent', ...baseRefs],
      dataSubjects: ['residents using sector services'],
      personalData: ['pairwise subject identifier per relying party', 'claims released per scope', 'sign-in events (factor, outcome)'],
      notHeld: ['the national identifier (never released)', 'a shared identifier across services'],
      recipients: rps.length ? rps : ['no relying parties configured'],
      retention,
      security,
      toComplete: ['each relying party’s own lawful basis for the claims it receives'],
    },
    {
      id: 'verification-and-presentation',
      purpose: 'Let any verifier confirm a credential is genuine and in force, and let a wallet present it',
      legalBasisRefs: baseRefs.length ? baseRefs : ['to be declared'],
      dataSubjects: ['credential holders'],
      personalData: ['status-list bit per credential (no identifier)', 'verification events naming the resident identifier when the credential carries it'],
      notHeld: ['who the verifier is, beyond its kind'],
      recipients: ['verifiers; federated peer jurisdictions', ...peers],
      retention,
      security,
      toComplete: [],
    },
    {
      id: 'delivery',
      purpose: 'Record whether and how the credential reached the holder',
      legalBasisRefs: baseRefs.length ? baseRefs : ['to be declared'],
      dataSubjects: ['residents'],
      personalData: ['resident identifier, channel, outcome, time, recording operator, failure reason, evidence reference'],
      notHeld: ['the holder’s wallet key'],
      recipients: ['the agency; counts by channel and status on the statistics report'],
      retention,
      security,
      toComplete: [],
    },
    {
      id: 'resident-access-log',
      purpose: 'Let a resident see who has looked at their record',
      legalBasisRefs: ['data-subject right of access'],
      dataSubjects: ['residents'],
      personalData: ['the resident’s own disclosure events, actors reduced to kinds'],
      notHeld: ['the identity of a member of staff'],
      recipients: ['the resident only, after proving control of the record'],
      retention,
      security,
      toComplete: [],
    },
    {
      id: 'audit-and-statistics',
      purpose: 'Hold operators to account and publish non-identifying statistics',
      legalBasisRefs: baseRefs.length ? baseRefs : ['legal obligation to maintain records; to be declared'],
      dataSubjects: ['residents (as targets of audited actions)', 'operators'],
      personalData: ['audit events: action, actor, target identifier, outcome, metadata; redacted on erasure', 'aggregate counts with small-cell suppression'],
      notHeld: ['names or dates of birth in the audit log or statistics'],
      recipients: ['auditors; the public, for suppressed aggregates'],
      retention: 'audit entries are redacted, never deleted, so the chain stays verifiable',
      security,
      toComplete: ['the suppression threshold the deployment publishes under (STATISTICS_SUPPRESSION_THRESHOLD)'],
    },
  ];
  const toComplete = [
    `hosting location and provider, and whether any processor is outside the country${profile.hostingNote ? ` (${profile.hostingNote})` : ''}`,
    'the SMS aggregator and any other processor, by name',
    'the data protection officer’s accreditation reference',
    `the ${profile.authority} registration number and tier, if not configured`,
    'the review date of this record',
  ];
  const out: RecordOfProcessing = {
    generatedAt: nowIso,
    status: 'factual skeleton generated from the live configuration; not a filing',
    controller,
    jurisdiction: cfg.countryName,
    law: profile.law,
    supervisoryAuthority: profile.authority,
    legalBases: bases,
    activities,
    toComplete,
  };
  if (cfg.dataProtection.processor) out.processor = cfg.dataProtection.processor;
  if (cfg.dataProtection.dpo) out.dataProtectionOfficer = cfg.dataProtection.dpo;
  if (cfg.dataProtection.supervisoryRegistration) out.supervisoryRegistration = cfg.dataProtection.supervisoryRegistration;
  return out;
}

/** The facts an impact assessment starts from, and which of the Directive's triggers apply. */
export function dpiaFacts(
  cfg: CountryConfig,
  profile: RegulatoryProfile = NEUTRAL_PROFILE,
  nowIso = new Date().toISOString(),
): DpiaFacts {
  const controller = cfg.dataProtection.controller ?? cfg.credential.issuerName;
  const residence = cfg.residency.residence;
  const biometrics = cfg.biometric.provider !== 'NONE';
  const modes: string[] = [];
  if (residence?.modes?.noFixedAbode?.allowed) modes.push('no_fixed_abode');
  if (residence?.modes?.referenceAddress?.allowed) modes.push('reference_address');
  const automated = permitsAutomatedDecisions({
    bindingRequired: cfg.residency.applicantBinding?.required ?? false,
    acceptedBindingMethods: cfg.residency.applicantBinding?.acceptedMethods ?? [],
    acceptedResidenceMethods: residence?.acceptedMethods ?? [],
  });
  const applies: Record<DpiaTriggerCondition, { applies: boolean; detail: string }> = {
    always: { applies: true, detail: '' },
    biometrics: { applies: biometrics, detail: biometrics ? ` (${cfg.biometric.provider})` : '; no biometric provider is configured' },
    vulnerable: { applies: true, detail: modes.length ? `; residence modes for people without an ordinary dwelling are admitted (${modes.join(', ')})` : '' },
    automated: { applies: automated, detail: automated ? '; the configured human review path applies' : '; every issuance decision under the accepted methods has a person in the loop' },
    new_technology: { applies: true, detail: '' },
  };
  const triggers: DpiaTrigger[] = profile.dpiaTriggers.map((t) => ({
    ground: t.ground,
    applies: applies[t.when].applies,
    because: applies[t.when].applies ? `${t.because}${applies[t.when].detail}` : `does not apply${applies[t.when].detail}`,
  }));
  const mitigations = [
    'national identifier tokenised; never stored or released in clear',
    'no origin or indigeneity field anywhere (ADR-0015)',
    'data minimisation in the credential: unit, assurance, binding, residence level and method; no address unless anchored; no residence mode or attester',
    'pairwise identifiers per relying party; claims released per consented scope',
    'consent with controller, processor, purpose, categories, evidence and legal basis; unregistered basis refused',
    'erasure destroys identifying fields and the address and redacts the audit trail without breaking the chain',
    'every refusal recorded with a reference, a reason and the appeal path; disputes restrict high-risk use',
    'resident can see who has looked at their record, by actor kind, with the audit event id',
    'statistics export with small-cell suppression; no identifier reaches it',
    'issuer keys in HSM/KMS; signed, scanned, attested container image',
  ];
  const toComplete = [
    'hosting location; any cross-border processor',
    'the officer’s assessment of inherent and residual risk per item in docs/templates/DPIA-TEMPLATE.md §4',
    'backup ageing or re-erasure procedure',
    'the human review process behind the configured appeal path',
    'the retention periods, where not configured',
    'consultation with data subjects or their representatives, as the law expects for high-risk processing',
  ];
  return {
    generatedAt: nowIso,
    status: 'factual skeleton generated from the live configuration; not an assessment',
    controller,
    jurisdiction: cfg.countryName,
    law: profile.law,
    supervisoryAuthority: profile.authority,
    triggers,
    processing: {
      purposes: ['residency enrolment and credential issuance', 'consent management', 'federated sign-in', 'credential verification and presentation', 'delivery recording', 'resident access log', 'audit and statistics'],
      categoriesOfDataSubject: ['residents and applicants', ...(modes.length ? ['persons with no fixed abode or using a reference address'] : []), 'operators (as actors in the audit log)'],
      categoriesOfPersonalData: PERSONAL_DATA_RESIDENT,
      specialCategoryData: biometrics ? ['biometric verification against the configured provider (templates not persisted here)'] : ['none held by this software'],
      recipients: [
        'the resident (credential, receipts, access log)',
        'the foundational identity authority (verification requests)',
        ...cfg.oidc.relyingParties.map((rp) => `relying party ${rp.name ?? rp.clientId} (${rp.sector})`),
        ...cfg.federation.trustedIssuers.map((p) => `federated peer ${p.name ?? p.did} (verification only)`),
      ],
      retention: retentionText(cfg, profile),
      automatedDecisionsPermitted: automated,
      humanReviewPath: cfg.credential.appealPath,
      residenceAnchor: residence?.anchor ?? 'unit',
      vulnerableSubjectModesAdmitted: modes,
      selfServiceFactors: [...cfg.selfService.accessLogFactors],
    },
    mitigationsInSoftware: mitigations,
    toComplete,
  };
}

/** The notification clock (72 hours unless the profile says otherwise), and whether subjects must be told at once. */
export function breachDeadlines(
  detectedAtIso: string,
  highRisk: boolean,
  hours = NEUTRAL_PROFILE.breachNotificationHours,
): { notifyAuthorityBy: string; notifySubjects: 'immediately' | 'not required unless risk rises' } {
  const t = Date.parse(detectedAtIso);
  return {
    notifyAuthorityBy: new Date(t + hours * 3_600_000).toISOString(),
    notifySubjects: highRisk ? 'immediately' : 'not required unless risk rises',
  };
}
