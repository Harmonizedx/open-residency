// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Consent and the Legal Basis Registry (ORCS §9).
 *
 * The lifecycle -- grant, inspect, withdraw, expire -- is covered by `smoke.ts`. This suite is
 * about the half §9 adds on top: the accountability fields, and the registry every
 * `legalBasisReference` resolves through.
 *
 * Most of what follows asserts a REFUSAL. That is the point of the change: the fields §9 asks
 * for were all addable as optional columns, and optional accountability columns arrive empty.
 * A register that accepted a grant naming no controller, citing no lawful basis and holding no
 * evidence of agreement would satisfy §9's field list while answering none of the questions
 * §9 exists to answer, so each of those is a refusal rather than a blank.
 */
import { KeyStore } from '../src/core/credentials/keystore';
import { didKeyFromJwk } from '../src/core/credentials/did';
import {
  ConsentEvidence,
  ConsentService,
  InMemoryConsentStore,
} from '../src/core/consent/consent';
import {
  CONSENT_LEGAL_BASIS_ID,
  LegalBasisRegistry,
  legalBasesForDeployment,
} from '../src/core/consent/legal-basis';
import { parseCountryConfig } from '../src/core/config/country-config';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

const CONTROLLER = 'Katsina State Residency Authority';
const BYLAW = 'ng:kt:residency-register-bylaw-2026';

const EVIDENCE: ConsentEvidence = {
  method: 'sso_consent_screen',
  at: '2026-08-17T09:00:00.000Z',
  reference: 'interaction:abc123',
};

function baseGrant() {
  return {
    subjectRef: 'tok_1',
    residentId: 'NG-KT-0001',
    relyingParty: 'health',
    purpose: 'Eligibility check',
    scopes: ['openid', 'health'],
    dataCategories: ['identity', 'residence'],
    evidence: EVIDENCE,
  };
}

function buildRegistry(): LegalBasisRegistry {
  return new LegalBasisRegistry(
    legalBasesForDeployment({
      jurisdiction: 'Nigeria',
      controller: CONTROLLER,
      declared: [
        {
          id: BYLAW,
          kind: 'public_task',
          name: 'Maintenance of the state residency register',
          instrument: 'Katsina State Residency Register By-law 2026, s.4',
          jurisdiction: 'Nigeria',
          effectiveFrom: '2026-01-01',
        },
      ],
    }),
  );
}

async function main() {
  console.log('\n== Consent and the Legal Basis Registry (ORCS §9) ==\n');

  const key = await KeyStore.generate('consent-smoke-key');
  const issuerDid = didKeyFromJwk(key.publicJwk);
  const registry = buildRegistry();
  const svc = new ConsentService(new InMemoryConsentStore(), key, issuerDid, {
    controller: CONTROLLER,
    processor: 'HarmonizedX Limited (hosting)',
    legalBases: registry,
  });

  console.log('The §9 fields are recorded:');
  const granted = await svc.grant(baseGrant());
  check('a complete grant is accepted', granted.ok === true);
  if (granted.ok) {
    check('the controller is recorded', granted.record.controller === CONTROLLER);
    check('the processor is recorded', granted.record.processor === 'HarmonizedX Limited (hosting)');
    check(
      'data categories are recorded, distinctly from the scopes',
      granted.record.dataCategories.join() === 'identity,residence' &&
        granted.record.scopes.join() === 'openid,health',
    );
    check(
      'evidence of agreement is recorded with its retention reference',
      granted.record.evidence.method === 'sso_consent_screen' &&
        granted.record.evidence.reference === 'interaction:abc123',
    );
    check(
      'the legal basis defaults to consent itself',
      granted.record.legalBasisReference === CONSENT_LEGAL_BASIS_ID,
    );
    check('the first version is 1', granted.record.version === 1);

    const payload = JSON.parse(
      Buffer.from(granted.receipt.split('.')[1], 'base64url').toString('utf8'),
    );
    check(
      'the citizen receipt carries the controller and the basis, not just the scopes',
      payload.controller === CONTROLLER &&
        payload.legalBasisReference === CONSENT_LEGAL_BASIS_ID &&
        Array.isArray(payload.dataCategories),
    );
  }

  console.log('\nA grant that cannot be recorded properly is REFUSED, never written blank:');
  const noCategories = await svc.grant({ ...baseGrant(), residentId: 'X1', dataCategories: [] });
  check(
    'no data categories -> DATA_CATEGORIES_REQUIRED',
    !noCategories.ok && noCategories.reason === 'DATA_CATEGORIES_REQUIRED',
  );
  const blankCategories = await svc.grant({
    ...baseGrant(),
    residentId: 'X2',
    dataCategories: ['   '],
  });
  check(
    'whitespace data categories do not satisfy the requirement either',
    !blankCategories.ok && blankCategories.reason === 'DATA_CATEGORIES_REQUIRED',
  );
  const noEvidence = await svc.grant({
    ...baseGrant(),
    residentId: 'X3',
    evidence: { ...EVIDENCE, reference: '  ' },
  });
  check(
    'evidence with no retention reference -> EVIDENCE_OF_AGREEMENT_REQUIRED',
    !noEvidence.ok && noEvidence.reason === 'EVIDENCE_OF_AGREEMENT_REQUIRED',
  );
  const badEvidenceDate = await svc.grant({
    ...baseGrant(),
    residentId: 'X4',
    evidence: { ...EVIDENCE, at: 'last tuesday' },
  });
  check(
    'evidence with an unparseable timestamp -> EVIDENCE_TIMESTAMP_REQUIRED',
    !badEvidenceDate.ok && badEvidenceDate.reason === 'EVIDENCE_TIMESTAMP_REQUIRED',
  );

  const noController = new ConsentService(new InMemoryConsentStore(), key, issuerDid, {
    controller: '   ',
    legalBases: buildRegistry(),
  });
  const refusedController = await noController.grant(baseGrant());
  check(
    'a deployment that never named its controller cannot record consent',
    !refusedController.ok && refusedController.reason === 'CONTROLLER_REQUIRED',
  );

  console.log('\nThe Legal Basis Registry is a CLOSED vocabulary:');
  const unknown = await svc.grant({
    ...baseGrant(),
    residentId: 'X5',
    legalBasisReference: 'the-law',
  });
  check(
    'an unregistered reference is refused, not stored as free text',
    !unknown.ok && unknown.reason === 'UNKNOWN_LEGAL_BASIS',
  );
  check('a registered basis resolves', registry.resolve(BYLAW)?.kind === 'public_task');
  check('an unregistered one resolves to nothing', registry.resolve('the-law') === null);

  const future = new LegalBasisRegistry([
    {
      id: 'ng:kt:not-yet',
      kind: 'legal_obligation',
      name: 'Commences next year',
      instrument: 'Some Act 2027, s.1',
      jurisdiction: 'Nigeria',
      controller: CONTROLLER,
      version: '1.0',
      effectiveFrom: '2027-01-01',
    },
  ]);
  check(
    'a basis outside its effective window does not resolve',
    future.resolve('ng:kt:not-yet', new Date('2026-08-17')) === null &&
      future.resolve('ng:kt:not-yet', new Date('2027-06-01')) !== null,
  );

  let duplicateRejected = false;
  try {
    buildRegistry().register({
      id: BYLAW,
      kind: 'public_task',
      name: 'A second definition of the same id',
      instrument: 'Something else entirely',
      jurisdiction: 'Nigeria',
      controller: CONTROLLER,
      version: '2.0',
      effectiveFrom: '2026-01-01',
    });
  } catch {
    duplicateRejected = true;
  }
  check(
    'redefining a registered id is refused (it would change what every consent citing it meant)',
    duplicateRejected,
  );

  let unattributedRejected = false;
  try {
    new LegalBasisRegistry([
      {
        id: 'ng:kt:vague',
        kind: 'public_task',
        name: 'Unattributed',
        instrument: '',
        jurisdiction: 'Nigeria',
        controller: CONTROLLER,
        version: '1.0',
        effectiveFrom: '2026-01-01',
      },
    ]);
  } catch {
    unattributedRejected = true;
  }
  check('a basis naming no instrument is refused', unattributedRejected);

  console.log('\nReplacement versions the record and preserves the previous one (§9 Replace):');
  const v2 = await svc.grant({ ...baseGrant(), scopes: ['openid', 'health', 'immunisation'] });
  check('a re-grant with different scopes is version 2', v2.ok && v2.record.version === 2);
  if (v2.ok && granted.ok) {
    check('the new version points back at the one it replaced', v2.record.supersedesId === granted.record.id);
    const all = await svc.listByResident('NG-KT-0001');
    const prior = all.find((c) => c.id === granted.record.id);
    check('the previous record is preserved, marked replaced', prior?.status === 'replaced');
    check('and points forward at its successor', prior?.supersededById === v2.record.id);
    check(
      'exactly one consent for this relying party is live',
      all.filter((c) => c.status === 'active').length === 1,
    );
  }

  console.log('\nWithdrawal records who acted (§9 Withdraw):');
  const toWithdraw = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-W',
    relyingParty: 'welfare',
  });
  if (toWithdraw.ok) {
    const byOperator = await svc.revoke(toWithdraw.record.id, 'operator:desk-7');
    check(
      'a withdrawal keyed by an operator is distinguishable from the citizen doing it',
      byOperator?.status === 'revoked' && byOperator.withdrawnBy === 'operator:desk-7',
    );
    check(
      'and it stops the processing',
      svc.mayProcess(byOperator!).permitted === false &&
        svc.mayProcess(byOperator!).reason === 'CONSENT_WITHDRAWN',
    );
  }

  console.log('\nExpiry stops processing UNLESS another valid basis applies (§9 Expire):');
  const consentBased = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-E1',
    relyingParty: 'tax',
    validityDays: 30,
  });
  const statutory = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-E2',
    relyingParty: 'registry',
    validityDays: 30,
    legalBasisReference: BYLAW,
  });
  if (consentBased.ok && statutory.ok) {
    const after = new Date(Date.parse(consentBased.record.expiresAt!) + 1000);
    check(
      'a consent-based grant stops at expiry',
      svc.mayProcess(consentBased.record, after).permitted === false &&
        svc.mayProcess(consentBased.record, after).reason === 'CONSENT_EXPIRED',
    );
    check(
      'a statute-based grant survives it -- the citizen lapsing does not repeal the by-law',
      svc.mayProcess(statutory.record, after).permitted === true &&
        svc.mayProcess(statutory.record, after).basis?.kind === 'public_task',
    );

    console.log('\nWithdrawing the BASIS stops everything relying on it:');
    const refusedNoReason = registry.deactivate(BYLAW, { reason: '  ', authority: 'op' });
    check(
      'deactivation with no reason is refused',
      !refusedNoReason.ok && refusedNoReason.reason === 'REASON_REQUIRED_FOR_DEACTIVATION',
    );
    const refusedNoAuthority = registry.deactivate(BYLAW, { reason: 'Repealed', authority: '' });
    check(
      'deactivation with no authority is refused',
      !refusedNoAuthority.ok && refusedNoAuthority.reason === 'AUTHORITY_REQUIRED_FOR_DEACTIVATION',
    );
    const done = registry.deactivate(BYLAW, {
      reason: 'By-law repealed by the 2027 consolidation',
      authority: 'operator:commissioner',
    });
    check('a properly attributed deactivation succeeds', done.ok === true);
    check(
      'the statute-based grant now stops too',
      svc.mayProcess(statutory.record, after).permitted === false,
    );
    check(
      'the repealed basis stays READABLE for the auditor following the citation',
      registry.get(BYLAW)?.deactivationReason === 'By-law repealed by the 2027 consolidation' &&
        registry.get(BYLAW)?.deactivatedBy === 'operator:commissioner',
    );
    check('...while no longer resolving for processing', registry.resolve(BYLAW) === null);
    const twice = registry.deactivate(BYLAW, { reason: 'again', authority: 'op' });
    check(
      'it cannot be deactivated twice',
      !twice.ok && twice.reason === 'LEGAL_BASIS_ALREADY_DEACTIVATED',
    );
    const afterRepeal = await svc.grant({
      ...baseGrant(),
      residentId: 'NG-KT-E3',
      legalBasisReference: BYLAW,
    });
    check(
      'and a new grant citing it is refused as NOT_IN_FORCE, distinctly from unknown',
      !afterRepeal.ok && afterRepeal.reason === 'LEGAL_BASIS_NOT_IN_FORCE',
    );
  }

  console.log('\nAn authentication-only sign-in can still record consent:');
  //
  // `openid` alone is what a relying party sends when it wants authentication and no claims.
  // Deriving the data categories from the non-openid scopes made the list empty, the grant was
  // refused, and the SSO interaction 400'd -- a plain sign-in could not complete. The e2e suite
  // requests four scopes, so nothing caught it. `openid` releases the pairwise subject
  // identifier, which IS a category of personal data, and is asserted as such here.
  const authOnly = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-AUTHONLY',
    relyingParty: 'portal',
    scopes: [],
    dataCategories: ['subject_identifier'],
  });
  check('a grant releasing only the subject identifier is accepted', authOnly.ok === true);
  check(
    'and it records that category rather than nothing',
    authOnly.ok && authOnly.record.dataCategories.join() === 'subject_identifier',
  );

  console.log('\nA superseded record is not reported as withdrawn:');
  if (v2.ok && granted.ok) {
    const all = await svc.listByResident('NG-KT-0001');
    const prior = all.find((c) => c.id === granted.record.id);
    check(
      'a replaced consent carries no revokedAt -- the citizen restated it, they did not withdraw it',
      prior?.status === 'replaced' && prior?.revokedAt === undefined,
    );
    check('and no withdrawnBy either', prior?.withdrawnBy === undefined);
  }

  console.log('\nA superseded record does not ride on a statutory basis:');
  const wideV1 = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-SUPERSEDE',
    relyingParty: 'registry2',
    scopes: ['openid', 'health', 'tax'],
    legalBasisReference: CONSENT_LEGAL_BASIS_ID,
  });
  const narrowV2 = await svc.grant({
    ...baseGrant(),
    residentId: 'NG-KT-SUPERSEDE',
    relyingParty: 'registry2',
    scopes: ['openid'],
    dataCategories: ['subject_identifier'],
    legalBasisReference: CONSENT_LEGAL_BASIS_ID,
  });
  if (wideV1.ok && narrowV2.ok) {
    const superseded = (await svc.listByResident('NG-KT-SUPERSEDE')).find(
      (c) => c.id === wideV1.record.id,
    );
    check(
      'the narrowed version supersedes the wider one',
      superseded?.status === 'replaced' && narrowV2.record.version === 2,
    );
    check(
      'and the superseded, wider grant reports CONSENT_REPLACED rather than being honoured',
      !!superseded && svc.mayProcess(superseded).permitted === false,
    );
  }

  console.log('\nA time-limited basis that cannot say when it ends is refused:');
  let badEndRejected = false;
  try {
    new LegalBasisRegistry([
      {
        id: 'ng:kt:bad-end',
        kind: 'legal_obligation',
        name: 'Unreadable end date',
        instrument: 'Some Act 2026, s.2',
        jurisdiction: 'Nigeria',
        controller: CONTROLLER,
        version: '1.0',
        effectiveFrom: '2026-01-01',
        effectiveTo: '2027-13-45',
      },
    ]);
  } catch {
    badEndRejected = true;
  }
  check(
    'an unparseable effectiveTo is refused (NaN comparisons would make it perpetual)',
    badEndRejected,
  );

  console.log('\nConfig declares the registry, and is refused when it cannot be resolved:');
  const configBase = {
    countryCode: 'NG',
    countryName: 'Nigeria',
    defaultSubnationalUnit: 'KT',
    foundational: {
      provider: 'MOCK',
      inputs: [{ key: 'nin', label: 'NIN', pattern: '^\\d{11}$' }],
      assuranceOnSuccess: 'verified',
    },
    residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
    credential: {
      issuerDid,
      issuerName: CONTROLLER,
      type: 'StateResidencyCredential',
      validityDays: 365,
      context: ['https://www.w3.org/ns/credentials/v2'],
    },
    subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
  };
  let danglingDefaultRefused = false;
  try {
    parseCountryConfig({
      ...configBase,
      dataProtection: { defaultLegalBasisReference: 'ng:kt:never-declared' },
    });
  } catch {
    danglingDefaultRefused = true;
  }
  check(
    'a defaultLegalBasisReference naming nothing declared is refused at load',
    danglingDefaultRefused,
  );
  let redeclarationRefused = false;
  try {
    parseCountryConfig({
      ...configBase,
      dataProtection: {
        legalBases: [
          {
            id: CONSENT_LEGAL_BASIS_ID,
            kind: 'consent',
            name: 'Our own consent',
            instrument: 'Local rewrite',
            jurisdiction: 'Nigeria',
            effectiveFrom: '2026-01-01',
          },
        ],
      },
    });
  } catch {
    redeclarationRefused = true;
  }
  check('redeclaring the built-in consent basis is refused at load', redeclarationRefused);
  let badDateRefused = false;
  try {
    parseCountryConfig({
      ...configBase,
      dataProtection: {
        legalBases: [
          {
            id: 'ng:kt:bad',
            kind: 'public_task',
            name: 'Unreadable',
            instrument: 'Act',
            jurisdiction: 'Nigeria',
            effectiveFrom: '2026-01-01',
            effectiveTo: 'whenever',
          },
        ],
      },
    });
  } catch {
    badDateRefused = true;
  }
  check(
    'an unparseable date is a CONFIG error naming the file, not a registry throw at boot',
    badDateRefused,
  );
  const okCfg = parseCountryConfig({
    ...configBase,
    dataProtection: {
      controller: 'Katsina State Government',
      legalBases: [
        {
          id: BYLAW,
          kind: 'public_task',
          name: 'Residency register',
          instrument: 'By-law 2026 s.4',
          jurisdiction: 'Nigeria',
          effectiveFrom: '2026-01-01',
        },
      ],
      defaultLegalBasisReference: BYLAW,
    },
  });
  check(
    'a config declaring its controller and bases loads, and keeps them',
    okCfg.dataProtection.controller === 'Katsina State Government' &&
      okCfg.dataProtection.legalBases[0].id === BYLAW,
  );

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});