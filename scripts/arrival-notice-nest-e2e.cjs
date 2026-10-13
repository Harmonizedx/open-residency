// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * Arrival notices over HTTP, against the real NestJS application on a real PostgreSQL.
 *
 * The smoke suite proves the service on two in-memory deployments; this proves the part a
 * peer and a registrar actually touch: the public route a peer posts a signed notice to and
 * what it refuses, the rule applied through the real lifecycle and store, the operator routes
 * and their guards, the outbound notice posted to the peer's declared endpoint, and the audit
 * trail. Run by scripts/run-sso-nest-e2e.sh after the other suites, on the same database.
 *
 * The peer is a key pair generated here: its public half is in the deployment's trust list,
 * its private half signs the notices and the peer credential this script presents.
 */
require('reflect-metadata');
const http = require('node:http');
const { writeFileSync, mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash, randomUUID } = require('node:crypto');
const jose = require('jose');

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

const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

async function main() {
  // The peer: Kano, as a key pair this script holds.
  const PEER_DID = 'did:web:id.kano.example';
  const HOME_DID = 'did:web:id.demoland.example';
  const peer = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const peerJwk = { ...(await jose.exportJWK(peer.publicKey)), kid: 'kano-key-1' };
  const stranger = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });

  // Where the deployment will post its own notices to the peer: a receiver this script runs.
  const received = [];
  const receiver = http.createServer((rq, rs) => {
    const chunks = [];
    rq.on('data', (c) => chunks.push(c));
    rq.on('end', () => {
      received.push({ url: rq.url, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
      rs.writeHead(201, { 'content-type': 'application/json' });
      rs.end('{"id":"ack"}');
    });
  });
  await new Promise((r) => receiver.listen(0, '127.0.0.1', r));
  const receiverUrl = `http://127.0.0.1:${receiver.address().port}/federation/arrival-notices`;

  const cfgDir = mkdtempSync(join(tmpdir(), 'ors-arrival-e2e-cfg-'));
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
  issuerDid: ${HOME_DID}
  issuerName: Demoland Residency Authority
  type: StateResidencyCredential
  validityDays: 365
  context: [https://www.w3.org/ns/credentials/v2]
  appealPath: 'Demoland Residency Authority, Appeals Desk'
subnationalUnits:
  - { code: DX, name: Demo District, parent: ZZ, level: state }
federation:
  trustedIssuers:
    - did: ${PEER_DID}
      name: Kano State Residency Authority
      publicJwks:
        - { kty: OKP, crv: Ed25519, x: "${peerJwk.x}", kid: kano-key-1 }
      arrivalNoticeUrl: ${receiverUrl}
      exclusivity: { rule: suspend, graceDays: 0 }
`,
  );
  process.env.NODE_ENV = 'test';
  process.env.COUNTRY_CONFIG_DIR = cfgDir;
  process.env.SUBJECT_PEPPER = 'arrival-e2e-subject-pepper';
  process.env.ISSUER_KEY_BACKEND = 'dev';
  process.env.OIDC_COOKIE_SECRET = 'arrival-e2e-cookie-secret-0123456789';
  process.env.ADMIN_API_KEY = 'arrival-e2e-admin-key';
  process.env.PUBLIC_BASE_URL = 'http://localhost:8080';
  process.env.ARRIVAL_NOTICE_SWEEP_SECONDS = '0';
  const { NestFactory } = require('@nestjs/core');
  const { json, urlencoded } = require('express');
  const { AppModule } = require('../dist/app.module');
  const app = await NestFactory.create(AppModule, { bodyParser: false, logger: false, abortOnError: false });
  app.use(json());
  app.use(urlencoded({ extended: false }));
  await app.listen(0, '127.0.0.1');
  const base = (await app.getUrl()).replace('[::1]', '127.0.0.1').replace('0.0.0.0', '127.0.0.1');
  console.log('\n== Arrival notices over HTTP (real NestJS app + Postgres) ==\n');

  const signNotice = async (key, kid, claims) =>
    new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'arrival-notice+jwt' })
      .setIssuedAt()
      .setExpirationTime('30d')
      .sign(key);

  try {
    const issued = await req('POST', `${base}/residency/issue`, {
      body: { countryCode: 'ZZ', subnationalUnit: 'DX', identifiers: { nationalId: '12345678902' } },
    });
    check('enrolment issues a residency', issued.status === 201 && issued.body.status === 'issued', `${issued.status} ${issued.text.slice(0, 120)}`);
    const A = issued.body.residentId;
    const credentialId = decode(issued.body.credentialJwt).jti;
    const hashOf = (jwt) => createHash('sha256').update(jwt, 'utf8').digest('base64url');
    const noticeClaims = () => ({
      iss: PEER_DID,
      aud: HOME_DID,
      jti: `urn:uuid:${randomUUID()}`,
      credentialId,
      presentationHash: hashOf(issued.body.credentialJwt),
      presentedAt: '2026-10-13T08:30:00.000Z',
      registeredAt: '2026-10-13T08:45:00.000Z',
    });
    const anon = { headers: { 'x-admin-key': '' } };

    console.log('\nWhat the public route refuses:');
    const garbage = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: 'not-a-jwt' } });
    check('a body that is not a compact JWT is a 400 from validation', garbage.status === 400);
    const asCredential = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: issued.body.credentialJwt } });
    check('a credential posted as a notice is refused by type (400 WRONG_TYPE)', asCredential.status === 400 && /WRONG_TYPE/.test(asCredential.text), asCredential.text.slice(0, 120));
    const fromStranger = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: await signNotice(stranger.privateKey, 'did:web:id.stranger.example#k', { ...noticeClaims(), iss: 'did:web:id.stranger.example' }) } });
    check('a notice from a jurisdiction not in the trust list is 401 UNTRUSTED_PEER', fromStranger.status === 401 && /UNTRUSTED_PEER/.test(fromStranger.text), fromStranger.text.slice(0, 120));
    const forged = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: await signNotice(stranger.privateKey, `${PEER_DID}#kano-key-1`, noticeClaims()) } });
    check("a notice naming the peer's key but not signed by it is 401 BAD_SIGNATURE", forged.status === 401 && /BAD_SIGNATURE/.test(forged.text), forged.text.slice(0, 120));
    const misaddressed = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: await signNotice(peer.privateKey, `${PEER_DID}#kano-key-1`, { ...noticeClaims(), aud: 'did:web:id.elsewhere.example' }) } });
    check('a notice addressed to another deployment is 401', misaddressed.status === 401 && /NOT_ADDRESSED/.test(misaddressed.text), misaddressed.text.slice(0, 120));
    const leaky = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: await signNotice(peer.privateKey, `${PEER_DID}#kano-key-1`, { ...noticeClaims(), fullName: 'A. Person' }) } });
    check('a notice carrying anything about the person is 400 UNEXPECTED_CLAIM', leaky.status === 400 && /UNEXPECTED_CLAIM_fullName/.test(leaky.text), leaky.text.slice(0, 120));
    const before = await req('GET', `${base}/residency/${A}/relationship`);
    check('  and through all of that the relationship stayed ACTIVE', before.status === 200 && before.body.relationship?.status === 'ACTIVE', before.text.slice(0, 160));

    console.log('\nA valid notice, under rule `suspend` with no grace period:');
    const good = await signNotice(peer.privateKey, `${PEER_DID}#kano-key-1`, noticeClaims());
    const accepted = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: good } });
    check('accepted without any operator credential: the signature is the credential', accepted.status === 201, accepted.text.slice(0, 160));
    check('  applied on receipt, naming the rule and the transition', accepted.body?.status === 'applied' && accepted.body?.rule === 'suspend' && accepted.body?.conflict === true && accepted.body?.appliedTransition === 'SUSPENDED', accepted.text.slice(0, 200));
    const noticeId = accepted.body?.id;
    const after = await req('GET', `${base}/residency/${A}/relationship`);
    check('  the relationship is SUSPENDED, decided by the rule in the name of the peer', after.body?.relationship?.status === 'SUSPENDED' && after.body?.relationship?.decidedBy === `rule:exclusivity:${PEER_DID}`, after.text.slice(0, 200));
    const replay = await req('POST', `${base}/federation/arrival-notices`, { ...anon, body: { notice: good } });
    check('  posting the same notice again is a 409 REPLAY', replay.status === 409 && /REPLAY/.test(replay.text), replay.text.slice(0, 120));

    console.log('\nThe operator routes:');
    const listed = await req('GET', `${base}/federation/arrival-notices?residentId=${A}`);
    check('GET /federation/arrival-notices lists the notice for the resident', listed.status === 200 && listed.body.total === 1 && listed.body.items[0].id === noticeId && listed.body.items[0].notice === good, listed.text.slice(0, 160));
    const one = await req('GET', `${base}/federation/arrival-notices/${encodeURIComponent(noticeId)}`);
    check('GET /federation/arrival-notices/{id} returns it as stored, with the signed notice', one.status === 200 && one.body.peerDid === PEER_DID && one.body.residentId === A && one.body.notice === good, one.text.slice(0, 160));
    const listedAnon = await req('GET', `${base}/federation/arrival-notices`, anon);
    check('  the listing is operator-guarded (401 without a credential)', listedAnon.status === 401);
    const badFilter = await req('GET', `${base}/federation/arrival-notices?status=bogus`);
    check('  an unknown status filter is a 400 from validation', badFilter.status === 400);
    const noReason = await req('POST', `${base}/federation/arrival-notices/${encodeURIComponent(noticeId)}/resolve`, { body: { resolution: 'reversed' } });
    check('resolving without a reason is a 400 from validation', noReason.status === 400);
    const reversed = await req('POST', `${base}/federation/arrival-notices/${encodeURIComponent(noticeId)}/resolve`, { body: { resolution: 'reversed', reason: 'The person works in Kano and lives here' } });
    check('reversing the suspension is 201 and resolved', reversed.status === 201 && reversed.body.status === 'resolved' && reversed.body.resolution === 'reversed' && typeof reversed.body.resolvedBy === 'string', reversed.text.slice(0, 160));
    const reinstated = await req('GET', `${base}/residency/${A}/relationship`);
    check('  and the relationship is ACTIVE again', reinstated.body?.relationship?.status === 'ACTIVE');
    const again = await req('POST', `${base}/federation/arrival-notices/${encodeURIComponent(noticeId)}/resolve`, { body: { resolution: 'upheld', reason: 'Changed my mind' } });
    check('  resolving twice is 400 ALREADY_RESOLVED', again.status === 400 && /ALREADY_RESOLVED/.test(again.text));
    const unknown = await req('GET', `${base}/federation/arrival-notices/urn:uuid:nobody`);
    check('  an unknown notice is 404', unknown.status === 404);

    console.log('\nTelling the peer (outbound):');
    // A credential the peer issued, which the mover presents at this desk.
    const peerCredential = await new jose.SignJWT({
      vc: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'StateResidencyCredential'],
        issuer: PEER_DID,
        credentialSubject: { id: 'did:example:holder', residentId: 'KN-PEER-0001-A', jurisdiction: { country: 'NG', subnationalUnit: 'KN' } },
      },
      iss: PEER_DID,
      sub: 'did:example:holder',
      jti: 'urn:uuid:peer-credential-1',
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: `${PEER_DID}#kano-key-1`, typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('365d')
      .sign(peer.privateKey);
    const own = await req('POST', `${base}/federation/arrival-notices/outbound`, { body: { countryCode: 'ZZ', credential: issued.body.credentialJwt } });
    check('a credential this deployment issued itself gets no notice (400 CREDENTIAL_IS_OURS)', own.status === 400 && /CREDENTIAL_IS_OURS/.test(own.text), own.text.slice(0, 120));
    const sent = await req('POST', `${base}/federation/arrival-notices/outbound`, { body: { countryCode: 'ZZ', credential: peerCredential, presentedAt: '2026-10-13T11:00:00.000Z', registeredAt: '2026-10-13T11:10:00.000Z' } });
    check("the peer's credential verifies and a notice is sent to the peer's declared endpoint", sent.status === 201 && sent.body.direction === 'outbound' && sent.body.status === 'sent' && sent.body.peerDid === PEER_DID && received.length === 1, sent.text.slice(0, 200));
    const delivered = received[0]?.body?.notice ?? '';
    const payload = delivered ? decode(delivered) : {};
    check('  signed by this deployment, addressed to the peer, naming the credential and nothing about the person', payload.iss === HOME_DID && payload.aud === PEER_DID && payload.credentialId === 'urn:uuid:peer-credential-1' && Object.keys(payload).sort().join(',') === 'aud,credentialId,exp,iat,iss,jti,presentationHash,presentedAt,registeredAt');
    const verified = await jose.jwtVerify(delivered, await jose.importJWK(JSON.parse((await req('GET', `${base}/.well-known/did.json`, anon)).text).verificationMethod[0].publicKeyJwk, 'EdDSA'), { issuer: HOME_DID, audience: PEER_DID, typ: 'arrival-notice+jwt' }).then(() => true).catch((e) => e.message);
    check("  and verifiable by anyone holding this deployment's published key", verified === true, String(verified));
    const outAnon = await req('POST', `${base}/federation/arrival-notices/outbound`, { ...anon, body: { countryCode: 'ZZ', credential: peerCredential } });
    check('  the outbound route is operator-guarded', outAnon.status === 401);
    const swept = await req('POST', `${base}/federation/arrival-notices/sweep`);
    check('the sweep runs and reports counts', swept.status === 201 && swept.body.applied === 0 && swept.body.resent === 0, swept.text.slice(0, 120));

    console.log('\nThe audit trail:');
    const audit = await req('GET', `${base}/audit?target=${A}&limit=50`);
    const actions = (audit.body?.events ?? audit.body?.items ?? audit.body ?? []).map((e) => e.action);
    check('receipt and resolution are on the record, attributed', audit.status === 200 && actions.includes('federation.arrival-notice.receive') && actions.includes('federation.arrival-notice.resolve'), `${audit.status} ${JSON.stringify(actions).slice(0, 200)}`);
  } finally {
    await app.close();
    receiver.close();
    rmSync(cfgDir, { recursive: true, force: true });
  }
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
