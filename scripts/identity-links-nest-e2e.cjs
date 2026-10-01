// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Identity links over HTTP, against the real NestJS application on a real PostgreSQL.
 *
 * The smoke suite proves the registry and the residency service; this proves the part a
 * registrar's console actually touches: the routes, their guards and validation, the
 * tokenization of a raw identifier on arrival, the audit trail, and that enrolment through
 * `POST /residency/issue` follows a correction made through these routes. Run by
 * scripts/run-sso-nest-e2e.sh after the SSO suites, on the same ephemeral database.
 */
require('reflect-metadata');
const http = require('node:http');
const { writeFileSync, mkdirSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

let pass = 0;
let fail = 0;
const check = (name, cond, detail) => {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
};

function req(method, url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const headers = { 'x-admin-key': process.env.ADMIN_API_KEY, ...opts.headers };
    const body = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    if (body !== undefined) {
      headers['content-length'] = String(Buffer.byteLength(body));
      headers['content-type'] = 'application/json';
    }
    const r = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try {
            json = text ? JSON.parse(text) : undefined;
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode, body: json, text });
        });
      },
    );
    r.on('error', reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

async function main() {
  const cfgDir = join(tmpdir(), `ors-links-e2e-cfg-${process.pid}`);
  mkdirSync(cfgDir, { recursive: true });
  writeFileSync(
    join(cfgDir, 'zz.yaml'),
    `countryCode: ZZ
countryName: Demoland
defaultSubnationalUnit: DX
foundational:
  provider: MOCK
  identifierType: NIN
  inputs: [{ key: nationalId, label: National ID }]
  assuranceOnSuccess: verified
residency:
  minAssurance: verified
  proofOfResidence: attestation
  humanReview:
    path: 'e2e fixture: reconsideration would be requested at the enrolment desk'
    withinDays: 30
credential:
  issuerDid: did:web:id.demoland.example
  issuerName: Demoland Residency Authority
  type: StateResidencyCredential
  validityDays: 365
  context: [https://www.w3.org/ns/credentials/v2]
  appealPath: 'Demoland Residency Authority, Appeals Desk'
subnationalUnits:
  - { code: DX, name: Demo District, parent: ZZ, level: state }
`,
  );
  process.env.NODE_ENV = 'test';
  process.env.COUNTRY_CONFIG_DIR = cfgDir;
  process.env.SUBJECT_PEPPER = 'links-e2e-subject-pepper';
  process.env.ISSUER_KEY_BACKEND = 'dev';
  process.env.OIDC_COOKIE_SECRET = 'links-e2e-cookie-secret-0123456789';
  process.env.ADMIN_API_KEY = 'links-e2e-admin-key';
  process.env.PUBLIC_BASE_URL = 'http://localhost:8080';

  const { NestFactory } = require('@nestjs/core');
  const { json, urlencoded } = require('express');
  const { AppModule } = require('../dist/app.module');
  const app = await NestFactory.create(AppModule, { bodyParser: false, logger: false });
  app.use(json());
  app.use(urlencoded({ extended: false }));
  await app.listen(0, '127.0.0.1');
  const base = (await app.getUrl()).replace('[::1]', '127.0.0.1').replace('0.0.0.0', '127.0.0.1');

  console.log('\n== Identity links over HTTP (real NestJS app + Postgres) ==\n');
  try {
    const issue = (nationalId) =>
      req('POST', `${base}/residency/issue`, {
        body: { countryCode: 'ZZ', subnationalUnit: 'DX', identifiers: { nationalId } },
      });

    // --- Enrolment creates the foundational link ------------------------------------------
    const a = await issue('12345678902');
    check('enrolment issues a residency', a.status === 201 && a.body.status === 'issued', `${a.status} ${a.text.slice(0, 120)}`);
    const A = a.body.residentId;
    const listA = await req('GET', `${base}/residency/${A}/identity-links`);
    check('GET /residency/{id}/identity-links lists the foundational link', listA.status === 200 && listA.body.links.length === 1 && listA.body.links[0].foundational === true);
    const foundationalA = listA.body.links[0];
    check('  the link holds a tokenized reference, never the number', foundationalA.identifierRef.startsWith('nin:') && !foundationalA.identifierRef.includes('12345678902'));
    check('  history has the LINK event, attributed', listA.body.history.length === 1 && listA.body.history[0].operation === 'LINK' && typeof listA.body.history[0].by === 'string');
    check('  no restriction while nothing is disputed', listA.body.restrictions.restricted === false);
    const anon = await req('GET', `${base}/residency/${A}/identity-links`, { headers: { 'x-admin-key': '' } });
    check('  the listing is operator-guarded (401 without a credential)', anon.status === 401);

    // --- LINK a sector identifier: tokenized on arrival, validated, idempotent -------------
    const noEvidence = await req('POST', `${base}/residency/${A}/identity-links`, {
      body: { identifierType: 'nhis', identifier: 'NHIS-000-777', evidenceRefs: [] },
    });
    check('LINK without evidence is a 400 EVIDENCE_REQUIRED', noEvidence.status === 400 && /EVIDENCE_REQUIRED/.test(noEvidence.text), noEvidence.text.slice(0, 120));
    const unknownField = await req('POST', `${base}/residency/${A}/identity-links`, {
      body: { identifierType: 'nhis', identifier: 'NHIS-000-777', evidenceRefs: ['card'], surprise: 1 },
    });
    check('  an undeclared body field is a 400 from the validation pipe', unknownField.status === 400);
    const linked = await req('POST', `${base}/residency/${A}/identity-links`, {
      body: { identifierType: 'NHIS', identifier: 'NHIS-000-777', evidenceRefs: ['nhis-card:scan-77'], reason: 'Card presented at clinic' },
    });
    check('LINK with evidence is 201 and created', linked.status === 201 && linked.body.created === true && linked.body.link.status === 'ACTIVE', linked.text.slice(0, 160));
    check('  identifierType is normalised and the raw identifier never comes back', linked.body.link.identifierType === 'nhis' && !linked.text.includes('NHIS-000-777'));
    const again = await req('POST', `${base}/residency/${A}/identity-links`, {
      body: { identifierType: 'nhis', identifier: 'NHIS-000-777', evidenceRefs: ['nhis-card:scan-77'] },
    });
    check('  linking the same identifier again is idempotent (created=false, same id)', again.status === 201 && again.body.created === false && again.body.link.id === linked.body.link.id);

    const b = await issue('12345678904');
    const B = b.body.residentId;
    const stolen = await req('POST', `${base}/residency/${B}/identity-links`, {
      body: { identifierType: 'nhis', identifier: 'NHIS-000-777', evidenceRefs: ['x'] },
    });
    check('  the same identifier on another person is 400 IDENTIFIER_LINKED_TO_ANOTHER_PERSON', stolen.status === 400 && /IDENTIFIER_LINKED_TO_ANOTHER_PERSON/.test(stolen.text));
    const one = await req('GET', `${base}/residency/identity-links/${linked.body.link.id}`);
    check('GET /residency/identity-links/{linkId} returns the link and its history', one.status === 200 && one.body.link.id === linked.body.link.id && one.body.history[0].operation === 'LINK');
    const missing = await req('GET', `${base}/residency/identity-links/00000000-0000-0000-0000-000000000000`);
    check('  an unknown link is a 404', missing.status === 404);

    // --- DISPUTE restricts issuance until resolved -----------------------------------------
    const disputed = await req('POST', `${base}/residency/identity-links/${foundationalA.id}/dispute`, { body: { reason: 'Applicant may have used a relative\'s number' } });
    check('DISPUTE is 201 and the link is DISPUTED', disputed.status === 201 && disputed.body.link.status === 'DISPUTED');
    const blocked = await issue('12345678902');
    check('  re-issuance for the person is refused with IDENTITY_LINK_DISPUTED', blocked.status === 201 && blocked.body.status === 'rejected' && blocked.body.reason === 'IDENTITY_LINK_DISPUTED', blocked.text.slice(0, 160));
    check('  the refusal is recorded with a reference the applicant can appeal with', typeof blocked.body.reference === 'string' && blocked.body.reference.length > 8);
    const restricted = await req('GET', `${base}/residency/${A}/identity-links`);
    check('  the listing reports the restriction and names the disputed link', restricted.body.restrictions.restricted === true && restricted.body.restrictions.disputedLinkIds.includes(foundationalA.id));
    const twice = await req('POST', `${base}/residency/identity-links/${foundationalA.id}/dispute`, { body: { reason: 'again' } });
    check('  disputing twice is a 400 ALREADY_DISPUTED', twice.status === 400 && /ALREADY_DISPUTED/.test(twice.text));
    const resolved = await req('POST', `${base}/residency/identity-links/${foundationalA.id}/dispute/resolve`, { body: { resolution: 'Applicant produced the enrolment slip' } });
    check('resolving the dispute is 201 and the link is ACTIVE with the resolver named', resolved.status === 201 && resolved.body.link.status === 'ACTIVE' && typeof resolved.body.link.dispute.resolvedBy === 'string');
    const unblocked = await issue('12345678902');
    check('  issuance is idempotent again (exists)', unblocked.body.status === 'exists' && unblocked.body.residentId === A);

    // --- MERGE, then enrolment follows the correction; SPLIT reverses it -------------------
    const merged = await req('POST', `${base}/residency/${A}/merge`, { body: { duplicateResidentId: B, reason: 'Same person enrolled twice; second number was a typo confirmed at the desk' } });
    check('MERGE is 201 with a merge record', merged.status === 201 && merged.body.merge.survivorRef === A && merged.body.merge.duplicateRef === B && merged.body.merge.moved.length === 1, merged.text.slice(0, 160));
    const mergeId = merged.body.merge && merged.body.merge.id;
    const relB = await req('GET', `${base}/residency/${B}/relationship`);
    check('  the duplicate\'s relationship is ENDED, naming the survivor', relB.status === 200 && relB.body.relationship.status === 'ENDED' && String(relB.body.relationship.endedReason).includes(A), relB.text.slice(0, 160));
    const credB = await req('GET', `${base}/residency/${B}/credential`);
    check('  the duplicate\'s credential is REPLACED by the survivor\'s', credB.status === 200 && credB.body.credentialStatus.status === 'REPLACED' && typeof credB.body.credentialStatus.supersededBy === 'string', credB.text.slice(0, 160));
    const viaB = await issue('12345678904');
    check('  enrolling with the merged number finds the survivor', viaB.body.status === 'exists' && viaB.body.residentId === A);
    const mergeView = await req('GET', `${base}/residency/merges/${mergeId}`);
    check('GET /residency/merges/{id} returns the merge, not yet split', mergeView.status === 200 && mergeView.body.split === undefined);
    const split = await req('POST', `${base}/residency/merges/${mergeId}/split`, { body: { reason: 'They were two people' } });
    check('SPLIT is 201 and the merge carries its split', split.status === 201 && !!split.body.merge.split);
    const reissued = await issue('12345678904');
    check('  the restored person re-enrols into a fresh relationship on their own record', reissued.body.status === 'issued' && reissued.body.residentId === B, reissued.text.slice(0, 160));
    const splitTwice = await req('POST', `${base}/residency/merges/${mergeId}/split`, { body: { reason: 'again' } });
    check('  splitting twice is a 400 ALREADY_SPLIT', splitTwice.status === 400 && /ALREADY_SPLIT/.test(splitTwice.text));

    // --- UNLINK the foundational identifier: suspend first, then the record stops matching -
    const listB = await req('GET', `${base}/residency/${B}/identity-links`);
    const foundationalB = listB.body.links.find((l) => l.foundational && l.status === 'ACTIVE');
    check('the restored person has an ACTIVE foundational link again', !!foundationalB);
    const unlinked = await req('POST', `${base}/residency/${B}/identity-links/${foundationalB.id}/unlink`, { body: { reason: 'Foundational record disowned by the register' } });
    check('UNLINK of the foundational identifier is 201 and reports the suspension', unlinked.status === 201 && unlinked.body.suspended === true && unlinked.body.link.status === 'UNLINKED', unlinked.text.slice(0, 160));
    const relB2 = await req('GET', `${base}/residency/${B}/relationship`);
    check('  the relationship is SUSPENDED, decided by the operator who unlinked', relB2.body.relationship.status === 'SUSPENDED' && typeof relB2.body.relationship.decidedBy === 'string', relB2.text.slice(0, 160));
    const fresh = await issue('12345678904');
    check('  the number no longer finds the suspended record and enrols afresh', fresh.body.status === 'issued' && fresh.body.residentId !== B);
    const wrongPerson = await req('POST', `${base}/residency/${A}/identity-links/${foundationalB.id}/unlink`, { body: { reason: 'x' } });
    check('  unlinking a link through a different person is a 400 LINK_NOT_FOR_PERSON', wrongPerson.status === 400 && /LINK_NOT_FOR_PERSON/.test(wrongPerson.text));

    // --- RELINK, and the closed link's history shows the move ------------------------------
    const relinked = await req('POST', `${base}/residency/identity-links/${linked.body.link.id}/relink`, {
      body: { residentId: B, reason: 'Adjudicated: the card is the second person\'s', evidenceRefs: ['adjudication:case-9'] },
    });
    check('RELINK is 201 with the closed source and the new link', relinked.status === 201 && relinked.body.from.status === 'UNLINKED' && relinked.body.to.personRef === B && relinked.body.to.supersedes === linked.body.link.id, relinked.text.slice(0, 160));
    const closedHistory = await req('GET', `${base}/residency/identity-links/${linked.body.link.id}`);
    check('  the closed link\'s history ends with the RELINK that moved it', closedHistory.body.history.map((e) => e.operation).join(',') === 'LINK,RELINK');

    // --- Audit ------------------------------------------------------------------------------
    const audit = await req('GET', `${base}/audit?limit=200`);
    const actions = new Set((audit.body.events || []).map((e) => e.action));
    check('every operation is in the audit log', ['identity.link', 'identity.link.dispute', 'identity.link.dispute.resolve', 'identity.link.unlink', 'identity.link.relink', 'identity.merge', 'identity.split'].every((x) => actions.has(x)), [...actions].filter((x) => x.startsWith('identity.')).join(','));
    check('  a refused operation is audited as a failure with its reason', (audit.body.events || []).some((e) => e.action === 'identity.link' && e.outcome === 'failure' && e.metadata && e.metadata.reason === 'EVIDENCE_REQUIRED'));
    check('  the raw sector identifier never reached the audit log', !audit.text.includes('NHIS-000-777'));
  } finally {
    await app.close();
    rmSync(cfgDir, { recursive: true, force: true });
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
