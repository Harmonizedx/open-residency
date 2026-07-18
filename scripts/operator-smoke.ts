/* eslint-disable no-console */
/**
 * Operator identity, pairwise subjects, and message delivery.
 *
 * These three land together because they are the pre-production gaps that were closed
 * together, and each one has a specific claim that has to be true:
 *
 *   OPERATOR   A privileged action can be attributed to a named person, roles actually
 *              restrict what that person can do, a second factor is enforced, and a key
 *              can be rotated with an overlap instead of a hard cutover.
 *
 *   PAIRWISE   Two relying parties see DIFFERENT subject identifiers for the same
 *              citizen, the same RP sees a STABLE one across sessions, and the mapping
 *              cannot be inverted or predicted without the deployment pepper.
 *
 *   MESSAGING  A one-time code is handed to a configured aggregator, the aggregator's
 *              own failure reporting is honoured, and the code never appears in a log
 *              line or an error message.
 */
import {
  OperatorService,
  OperatorStore,
  OperatorRecord,
  OperatorKeyRecord,
  operatorActor,
  operatorHasRole,
} from '../src/core/operator/operator';
import { totpCode, verifyTotp, base32Encode, generateTotpSecret } from '../src/core/operator/totp';
import { pairwiseSubject } from '../src/core/sso/pairwise';
import { GenericHttpProvider, buildMessagingProvider } from '../src/core/messaging/providers';
import { MessagingOtpSender } from '../src/core/messaging/otp-sender';
import { encryptContact, decryptContact } from '../src/core/messaging/contact-directory';
import { ContactDirectory, MessagingProvider, OutboundMessage } from '../src/core/messaging/types';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? ` -- ${detail}` : ''}`);
  }
}

/** In-memory OperatorStore, so this suite needs no database. */
class MemOperatorStore implements OperatorStore {
  ops = new Map<string, OperatorRecord>();
  keys = new Map<string, OperatorKeyRecord>();

  async findById(id: string) {
    return this.ops.get(id) ?? null;
  }
  async findByEmail(email: string) {
    return [...this.ops.values()].find((o) => o.email === email) ?? null;
  }
  async list() {
    return [...this.ops.values()];
  }
  async count() {
    return this.ops.size;
  }
  async create(r: OperatorRecord) {
    this.ops.set(r.id, { ...r });
  }
  async update(r: OperatorRecord) {
    this.ops.set(r.id, { ...r });
  }
  async findKeyByHash(h: string) {
    return [...this.keys.values()].find((k) => k.keyHash === h) ?? null;
  }
  async findKeyById(id: string) {
    return this.keys.get(id) ?? null;
  }
  async listKeys(operatorId: string) {
    return [...this.keys.values()].filter((k) => k.operatorId === operatorId);
  }
  async createKey(r: OperatorKeyRecord) {
    this.keys.set(r.id, { ...r });
  }
  async updateKey(r: OperatorKeyRecord) {
    this.keys.set(r.id, { ...r });
  }
}

async function totpSuite() {
  console.log('\nTOTP (RFC 6238):');

  // RFC 6238 Appendix B test vectors, SHA-1. The RFC's secret is the ASCII string
  // "12345678901234567890"; these are the published codes at those Unix times.
  const secret = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
  const vectors: Array<[number, string]> = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ];
  for (const [unix, expected] of vectors) {
    const got = totpCode(secret, unix * 1000);
    check(`RFC vector at t=${unix} is ${expected}`, got === expected, `got ${got}`);
  }

  const live = generateTotpSecret();
  const now = Date.now();
  check('a freshly generated code verifies', verifyTotp(live, totpCode(live, now), now));
  check('a wrong code does not verify', !verifyTotp(live, '000000', now));
  check('a non-numeric code does not verify', !verifyTotp(live, 'abcdef', now));
  // One step either side is accepted for clock skew; two is not.
  check(
    'a code from the previous step still verifies (clock skew)',
    verifyTotp(live, totpCode(live, now - 30_000), now),
  );
  check(
    'a code from four steps ago does NOT verify',
    !verifyTotp(live, totpCode(live, now - 120_000), now),
  );
}

async function operatorSuite() {
  console.log('\nOperator identity:');
  const store = new MemOperatorStore();
  const svc = new OperatorService(store, { requireMfa: true, issuerName: 'Test' });

  const { record, totpSecret } = await svc.createOperator({
    email: 'ada@katsina.gov.ng',
    displayName: 'Ada Registrar',
    roles: ['registrar'],
    password: 'correct horse battery staple',
  });
  check('an operator is created with the roles given', record.roles.join() === 'registrar');

  // The whole point: an action can name a person.
  const asOperator = { id: record.id, displayName: 'Ada Registrar', roles: ['registrar' as const], via: 'local' as const };
  check(
    'the audit actor names the operator, not a shared key',
    operatorActor(asOperator) === 'operator:Ada Registrar',
  );

  // MFA is enforced, and enforcement is not bypassable by omitting the field.
  const noMfa = await svc.login('ada@katsina.gov.ng', 'correct horse battery staple');
  check('login without a second factor is refused', !noMfa.ok && noMfa.reason === 'MFA_REQUIRED');

  const wrongPw = await svc.login('ada@katsina.gov.ng', 'wrong', totpCode(totpSecret));
  check('login with a wrong password is refused', !wrongPw.ok && wrongPw.reason === 'BAD_PASSWORD');

  const wrongMfa = await svc.login('ada@katsina.gov.ng', 'correct horse battery staple', '000000');
  check('login with a wrong TOTP is refused', !wrongMfa.ok && wrongMfa.reason === 'BAD_MFA');

  const good = await svc.login(
    'ada@katsina.gov.ng',
    'correct horse battery staple',
    totpCode(totpSecret),
  );
  check('login with password + TOTP succeeds', good.ok);

  // Roles restrict. A registrar may enrol; only a revoker (or admin) may revoke.
  const op = good.ok ? good.operator : asOperator;
  check('a registrar passes the registrar check', operatorHasRole(op, 'registrar'));
  check('a registrar FAILS the revoker check', !operatorHasRole(op, 'revoker'));
  check(
    'an admin satisfies every role check',
    operatorHasRole({ ...op, roles: ['admin'] }, 'revoker') &&
      operatorHasRole({ ...op, roles: ['admin'] }, 'auditor'),
  );

  // Lockout bounds guessing against the password.
  for (let i = 0; i < 5; i++) await svc.login('ada@katsina.gov.ng', 'wrong', totpCode(totpSecret));
  const locked = await svc.login(
    'ada@katsina.gov.ng',
    'correct horse battery staple',
    totpCode(totpSecret),
  );
  check(
    'the account locks after repeated failures, even for the right password',
    !locked.ok && locked.reason === 'LOCKED',
  );

  // ---- API keys and rotation ----
  console.log('\nOperator API keys:');
  const admin = await svc.createOperator({
    email: 'kiosk@katsina.gov.ng',
    roles: ['registrar'],
  });
  const issued = await svc.issueKey({ operatorId: admin.record.id, label: 'ward-3-kiosk' });
  check('a key is issued', !!issued);
  const authed = await svc.authenticateKey(issued!.key);
  check('the key authenticates to its own operator', authed?.id === admin.record.id);
  check('the key carries the operator identity, not a generic admin', authed?.via === 'apiKey');
  check('a wrong key does not authenticate', (await svc.authenticateKey('ork_nope')) === null);

  // Rotation with overlap is the property the shared static key could not offer.
  const rotated = await svc.rotateKey(issued!.record.id, 24);
  check('rotation issues a replacement key', !!rotated && rotated.key !== issued!.key);
  check(
    'the OLD key still works during the overlap window',
    (await svc.authenticateKey(issued!.key)) !== null,
  );
  check('the NEW key works immediately', (await svc.authenticateKey(rotated!.key)) !== null);
  check('the replacement records what it replaced', rotated!.record.rotatedFrom === issued!.record.id);

  await svc.revokeKey(issued!.record.id);
  check('a revoked key stops working', (await svc.authenticateKey(issued!.key)) === null);
  check('revoking one key leaves the other working', (await svc.authenticateKey(rotated!.key)) !== null);

  // Disabling the operator kills every key they hold, without touching the keys.
  await svc.setDisabled(admin.record.id, true);
  check(
    'disabling the operator disables their keys too',
    (await svc.authenticateKey(rotated!.key)) === null,
  );
}

async function pairwiseSuite() {
  console.log('\nPairwise subject identifiers:');
  const pepper = 'deployment-pepper';
  const resident = 'KT-7F3A-9K2P-4';

  const health = pairwiseSubject(pepper, 'health', resident);
  const tax = pairwiseSubject(pepper, 'tax', resident);

  check('two relying parties see DIFFERENT subjects for one citizen', health !== tax);
  check(
    'the same relying party sees a STABLE subject across sessions',
    pairwiseSubject(pepper, 'health', resident) === health,
  );
  check('the subject is not the residency id', health !== resident && !health.includes(resident));
  check(
    'a different deployment pepper yields a different subject',
    pairwiseSubject('other-pepper', 'health', resident) !== health,
  );
  check(
    'two citizens at the same RP get different subjects',
    pairwiseSubject(pepper, 'health', 'KT-0000-0000-0') !== health,
  );

  // The length-prefix guards a real collision: without it, ("ab","cd") and ("a","bcd")
  // would hash the same input and two different citizen/service pairs would share a sub.
  check(
    'client id and resident id cannot be confused for one another',
    pairwiseSubject(pepper, 'ab', 'cd') !== pairwiseSubject(pepper, 'a', 'bcd'),
  );
}

async function messagingSuite() {
  console.log('\nMessage delivery:');

  // A fake aggregator that records what it was asked to send.
  const sent: OutboundMessage[] = [];
  const provider: MessagingProvider = {
    code: 'GENERIC_HTTP',
    async send(m) {
      sent.push(m);
      return { channel: 'sms:test', providerMessageId: 'msg-1' };
    },
  };
  const directory: ContactDirectory = {
    async lookup(residentId) {
      return residentId === 'KT-7F3A-9K2P-4' ? '+2348030000001' : null;
    },
  };

  const sender = new MessagingOtpSender(provider, directory, 'Code {code} from {issuer}', 'Katsina');
  const { channel } = await sender.send('KT-7F3A-9K2P-4', '123456');
  check('the code is handed to the aggregator', sent.length === 1);
  check('it is addressed to the resident\'s number', sent[0].to === '+2348030000001');
  check('the code is in the message body', sent[0].body.includes('123456'));
  check('the template is applied', sent[0].body === 'Code 123456 from Katsina');
  check('it is routed as transactional traffic', sent[0].kind === 'otp');
  check('the channel is reported back for the audit trail', channel === 'sms:test');

  // A resident with no number must fail loudly, not silently succeed -- silently
  // succeeding is exactly what the old logging stub did.
  let threw = false;
  try {
    await sender.send('KT-UNKNOWN', '999999');
  } catch {
    threw = true;
  }
  check('a resident with no contact number raises rather than pretending', threw);
  check('nothing was sent for that resident', sent.length === 1);

  // The aggregator's own in-band failure reporting must be honoured: several answer
  // HTTP 200 with an error payload, and treating that as success loses codes silently.
  const rejecting = new GenericHttpProvider({
    provider: 'GENERIC_HTTP',
    baseUrl: 'http://127.0.0.1:9',
    request: {
      method: 'POST',
      path: '/send',
      successFlag: { path: 'status', equals: 'accepted' },
    },
  });
  let rejectedProperly = false;
  try {
    await rejecting.send({ to: '+2348030000001', body: 'x', kind: 'otp' });
  } catch (e) {
    // Unreachable host here, but the important property is that it raises rather than
    // returning a delivery result -- and that the error does not echo the body.
    rejectedProperly = !String((e as Error).message).includes('x');
  }
  check('an unreachable aggregator raises, and does not echo the message body', rejectedProperly);

  check(
    'a config-only aggregator can be built with no code change',
    buildMessagingProvider({
      provider: 'GENERIC_HTTP',
      baseUrl: 'https://sms.example.ng',
      request: { method: 'POST', path: '/v1/messages' },
    }) instanceof GenericHttpProvider,
  );

  // ---- contact encryption ----
  console.log('\nContact number encryption:');
  process.env.CONTACT_ENCRYPTION_KEY = 'a'.repeat(64);
  const blob = encryptContact('+2348030000001');
  check('the ciphertext is not the number', !blob.includes('2348030000001'));
  check('it round-trips under the right key', decryptContact(blob) === '+2348030000001');
  check('two encryptions of one number differ (fresh IV)', encryptContact('+2348030000001') !== blob);

  process.env.CONTACT_ENCRYPTION_KEY = 'b'.repeat(64);
  check('it does not decrypt under a different key', decryptContact(blob) === null);

  process.env.CONTACT_ENCRYPTION_KEY = 'a'.repeat(64);
  const parts = blob.split('.');
  const tampered = `${parts[0]}.${parts[1]}.${parts[2]}.${Buffer.from('tampered').toString('base64url')}`;
  check('tampered ciphertext is rejected by the GCM tag', decryptContact(tampered) === null);
  delete process.env.CONTACT_ENCRYPTION_KEY;
}

async function main() {
  console.log('Operator auth, pairwise subjects, and messaging\n' + '='.repeat(48));
  await totpSuite();
  await operatorSuite();
  await pairwiseSuite();
  await messagingSuite();
  console.log(`\n${pass} passed, ${fail} failed\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
