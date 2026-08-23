/* eslint-disable no-console */
/**
 * Rate limiting counts the caller, not the proxy (ADR-0013, #141).
 *
 * The defect these assertions replace was not a wrong limit -- it was a limit that was wrong
 * and looked right. Behind the ingress this project documents, every request presented the
 * ingress pod's address, so 120/min was one bucket for the whole deployment and any single
 * client could 429 everyone. Nothing failed, nothing logged.
 */
import { callerKey } from '../src/core/ratelimit/caller-key';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function main(): void {
  console.log('\n== Rate-limit caller identification ==\n');

  console.log('An authenticated caller is budgeted individually:');
  const opA = callerKey({ credential: 'ork_aaa', remoteAddress: '10.0.0.1', trustedHops: 0 });
  const opB = callerKey({ credential: 'ork_bbb', remoteAddress: '10.0.0.1', trustedHops: 0 });
  check('an operator key keys on the operator, not the address', opA.source === 'operator');
  check(
    'two operators behind one address do not share a budget',
    opA.key !== opB.key,
    'a ward office behind one NAT is a single address',
  );
  check(
    'the same operator gets the same bucket across requests',
    callerKey({ credential: 'ork_aaa', remoteAddress: '10.9.9.9', trustedHops: 0 }).key === opA.key,
  );
  check(
    'the credential is never the key itself',
    !opA.key.includes('ork_aaa'),
    'rate-limit keys reach memory, logs and metrics',
  );

  console.log('\nAn anonymous caller keys on an address the deployment can trust:');
  const direct = callerKey({ remoteAddress: '203.0.113.9', trustedHops: 0 });
  check('with no proxy declared, the socket address is used', direct.key === 'ip:203.0.113.9');

  // The whole point. X-Forwarded-For is client-supplied.
  const spoofed = callerKey({
    forwardedFor: '1.2.3.4',
    remoteAddress: '203.0.113.9',
    trustedHops: 0,
  });
  check(
    'a forged X-Forwarded-For cannot change the bucket when no proxy is declared',
    spoofed.key === 'ip:203.0.113.9',
    'this is what `trust proxy: true` would have allowed',
  );
  check('and the mismatch is reported rather than absorbed', spoofed.proxyMismatch === true);

  // One proxy: it appended the client's address and we speak to the proxy itself.
  const behindOne = callerKey({
    forwardedFor: '198.51.100.7',
    remoteAddress: '10.0.0.5',
    trustedHops: 1,
  });
  check(
    'with one proxy declared, the client address is read from the chain',
    behindOne.key === 'ip:198.51.100.7',
  );
  check('and a correctly configured deployment reports no mismatch', behindOne.proxyMismatch === false);

  // Counting from the right is what makes the reading unforgeable: a caller can prepend
  // anything, but cannot remove the entries real proxies appended.
  const prepended = callerKey({
    forwardedFor: 'evil, 198.51.100.7',
    remoteAddress: '10.0.0.5',
    trustedHops: 1,
  });
  check(
    'a caller prepending entries cannot steer the key past the declared hops',
    prepended.key === 'ip:198.51.100.7',
    prepended.key,
  );
  check(
    'specifically, the forged leftmost entry is never used',
    prepended.key !== 'ip:evil',
    'trusting the leftmost is exactly the blanket-trust failure',
  );

  const shortChain = callerKey({
    forwardedFor: '198.51.100.7',
    remoteAddress: '10.0.0.5',
    trustedHops: 3,
  });
  check(
    'a chain shorter than the declared hops does not read past its start',
    shortChain.key === 'ip:198.51.100.7',
  );

  console.log('\nDegenerate input fails closed rather than open:');
  const nothing = callerKey({ trustedHops: 0 });
  check(
    'no credential and no address is one shared bucket, not an unlimited one',
    nothing.source === 'unattributable' && nothing.key === 'anon:unattributable',
  );
  check(
    'a negative or nonsense hop count is treated as none declared',
    callerKey({ forwardedFor: '1.2.3.4', remoteAddress: '9.9.9.9', trustedHops: -5 }).key ===
      'ip:9.9.9.9',
  );

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  if (fail > 0) process.exit(1);
}

main();
