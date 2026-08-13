/* eslint-disable no-console */
/**
 * MOSIP ID Authentication, driven against a server that actually opens the envelope.
 *
 * The point of this test is that it cannot pass by accident. The fake IDA here does what
 * the real one does with an inbound request: decrypts the session key with its own private
 * key, decrypts the request block with that session key, recomputes the digest and compares
 * it to the decrypted `requestHMAC`, checks the certificate thumbprint identifies its key,
 * and verifies the detached JWS in the `signature` header against the partner certificate.
 * Every one of those fails closed. A client that prepends the GCM IV instead of appending
 * it, or lower-cases the digest, or pads its base64, does not "mostly work" here -- it
 * fails, which is exactly what it would do against a real deployment.
 *
 * What this cannot establish is that MOSIP accepts THIS deployment's partner identity: that
 * needs a MISP licence key, a partner id, a policy-linked API key and certificates uploaded
 * through the partner portal, none of which CI can hold. The envelope is verified here; the
 * partner agreement is not, and docs/INTEGRATION.md says so.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createVerify,
  generateKeyPairSync,
  privateDecrypt,
  constants as cryptoConstants,
  X509Certificate,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MosipIdaAdapter, mosipDigest } from '../src/core/foundational/adapters/mosip-ida.adapter';
import { ProviderRegistry } from '../src/core/foundational/registry';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
}

const UIN = '9830872690';
const OTP = '111111';

/** A self-signed certificate + key, the way partner onboarding would hand you one. */
function selfSignedCert(cn: string): { certPem: string; keyPem: string } {
  const dir = mkdtempSync(join(tmpdir(), 'ida-smoke-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  writeFileSync(keyPath, privateKey);
  execFileSync('openssl', [
    'req', '-new', '-x509', '-key', keyPath, '-out', certPath,
    '-days', '2', '-subj', `/CN=${cn}`,
  ]);
  return {
    keyPem: privateKey,
    certPem: require('node:fs').readFileSync(certPath, 'utf8') as string,
  };
}

/** MOSIP's symmetric decrypt: the IV is the LAST 16 bytes, after ciphertext and tag. */
function mosipSymmetricDecrypt(key: Buffer, blob: Buffer): Buffer {
  const iv = blob.subarray(blob.length - 16);
  const withTag = blob.subarray(0, blob.length - 16);
  const tag = withTag.subarray(withTag.length - 16);
  const ciphertext = withTag.subarray(0, withTag.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

interface Received {
  requestBlock?: Record<string, unknown>;
  hmacMatched?: boolean;
  thumbprintMatched?: boolean;
  signatureVerified?: boolean;
  signatureHeader?: string;
  path?: string;
  requestedAuth?: Record<string, boolean>;
  transactionID?: string;
  base64Unpadded?: boolean;
}

async function main() {
  console.log('\nMOSIP ID Authentication (envelope opened by the server):\n');

  const ida = selfSignedCert('ida-partner-cert');
  const partner = selfSignedCert('openresidency-partner');
  const idaPrivate = createPrivateKey(ida.keyPem);
  const idaThumbprint = createHash('sha256')
    .update(new X509Certificate(ida.certPem).raw)
    .digest();

  process.env.IDA_MISP_LICENSE_KEY = 'misp-licence-key';
  process.env.IDA_PARTNER_API_KEY = 'partner-api-key';
  process.env.IDA_SIGNING_KEY = partner.keyPem;

  const received: Received = {};
  let authStatus = true;
  let authErrors: { errorCode: string; errorMessage: string }[] = [];

  const server: Server = createServer(async (req, res) => {
    const body = await new Promise<string>((resolve) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => resolve(data));
    });
    received.path = req.url;

    // ---- The signature header, verified as MOSIP would ---------------------
    const signature = req.headers.signature as string | undefined;
    received.signatureHeader = signature;
    if (signature) {
      const [header, payload, sig] = signature.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
      const verifier = createVerify('RSA-SHA256');
      verifier.update(Buffer.concat([Buffer.from(`${header}.`, 'utf8'), Buffer.from(body, 'utf8')]));
      verifier.end();
      const cert = Buffer.from(decodedHeader.x5c[0], 'base64');
      const certPem = `-----BEGIN CERTIFICATE-----\n${cert
        .toString('base64')
        .replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
      received.signatureVerified =
        payload === '' &&
        decodedHeader.b64 === false &&
        Array.isArray(decodedHeader.crit) &&
        decodedHeader.crit.includes('b64') &&
        verifier.verify(new X509Certificate(certPem).publicKey, Buffer.from(sig, 'base64url'));
    }

    const parsed = JSON.parse(body) as Record<string, string> & {
      requestedAuth?: Record<string, boolean>;
    };

    if ((req.url ?? '').includes('/idauthentication/v1/otp/')) {
      received.transactionID = parsed.transactionID;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ response: { maskedMobile: 'XXXXXX7890' }, errors: [] }));
      return;
    }

    // ---- The envelope ------------------------------------------------------
    received.requestedAuth = parsed.requestedAuth;
    received.transactionID = parsed.transactionID;
    // MOSIP's encoder is URL-safe and unpadded; a padded field would be a different string.
    received.base64Unpadded = !/[+/=]/.test(
      `${parsed.request}${parsed.requestHMAC}${parsed.requestSessionKey}${parsed.thumbprint}`,
    );
    received.thumbprintMatched = Buffer.from(parsed.thumbprint, 'base64url').equals(idaThumbprint);

    try {
      const sessionKey = privateDecrypt(
        { key: idaPrivate, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(parsed.requestSessionKey, 'base64url'),
      );
      const plaintext = mosipSymmetricDecrypt(
        sessionKey,
        Buffer.from(parsed.request, 'base64url'),
      );
      received.requestBlock = JSON.parse(plaintext.toString('utf8'));
      const sentDigest = mosipSymmetricDecrypt(
        sessionKey,
        Buffer.from(parsed.requestHMAC, 'base64url'),
      ).toString('utf8');
      received.hmacMatched = sentDigest === mosipDigest(plaintext);
    } catch (e) {
      received.requestBlock = undefined;
      received.hmacMatched = false;
      console.log(`      [server] envelope failed to open: ${(e as Error).message}`);
    }

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        id: 'mosip.identity.auth',
        transactionID: parsed.transactionID,
        responseTime: new Date().toISOString(),
        response: { authStatus, authToken: 'auth-token-1' },
        errors: authErrors,
      }),
    );
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const providerConfig = {
    code: 'MOSIP_IDA',
    baseUrl,
    assuranceOnSuccess: 'high' as const,
    extra: {
      mispLicenseKeyEnv: 'IDA_MISP_LICENSE_KEY',
      partnerId: 'openresidency-partner',
      partnerApiKeyEnv: 'IDA_PARTNER_API_KEY',
      idaCertificatePem: ida.certPem,
      signingKeyEnv: 'IDA_SIGNING_KEY',
      signingCertificatePem: partner.certPem,
      domainUri: baseUrl,
      environment: 'Developer',
      individualIdType: 'UIN' as const,
    },
  };

  const adapter = new MosipIdaAdapter('test-pepper');
  adapter.init(providerConfig);

  // ---- OTP request ---------------------------------------------------------
  const challenge = await adapter.initiateChallenge({
    countryCode: 'NG',
    identifiers: { individualId: UIN },
  });
  check('an OTP is requested through the OTP endpoint', (received.path ?? '').includes('/idauthentication/v1/otp/'));
  check(
    'the path carries the MISP licence key, partner id and API key',
    (received.path ?? '').includes('misp-licence-key') &&
      (received.path ?? '').includes('openresidency-partner') &&
      (received.path ?? '').includes('partner-api-key'),
    received.path,
  );
  check('the OTP request is signed, and the signature verifies', received.signatureVerified === true);
  check(
    'the challenge reference is MOSIP\'s transaction id, which correlates the two calls',
    challenge.challengeRef === received.transactionID,
  );

  // ---- Authentication ------------------------------------------------------
  const result = await adapter.verify({
    countryCode: 'NG',
    identifiers: { individualId: UIN, otp: OTP, name: 'Amina Bello', dob: '1990/04/11' },
    challengeRef: challenge.challengeRef,
  });

  check('the authentication succeeds', result.verified, result.reason);
  check('the request block decrypted on the server', !!received.requestBlock);
  check('the OTP arrived inside the encrypted block, not in the clear', received.requestBlock?.otp === OTP);
  check(
    'demographics arrived inside the encrypted block',
    JSON.stringify(received.requestBlock?.demographics) ===
      JSON.stringify({ name: 'Amina Bello', dob: '1990/04/11' }),
    JSON.stringify(received.requestBlock?.demographics),
  );
  check('the digest matches the block that was sent', received.hmacMatched === true);
  check('the certificate thumbprint identifies the key we encrypted to', received.thumbprintMatched === true);
  check('every base64 field is URL-safe and unpadded', received.base64Unpadded === true);
  check('the body signature verifies against the partner certificate', received.signatureVerified === true);
  check(
    'requestedAuth declares what was actually sent',
    received.requestedAuth?.otp === true &&
      received.requestedAuth?.demo === true &&
      received.requestedAuth?.bio === false,
    JSON.stringify(received.requestedAuth),
  );
  check(
    'the OTP call and the auth call share one transaction id',
    received.transactionID === challenge.challengeRef,
  );

  check(
    'success is authoritative authentication, not a lookup',
    result.applicantBinding?.method === 'authoritative_authentication',
  );
  check('the assurance configured for this provider is applied', result.assuranceLevel === 'high');
  check(
    'the raw identity number is never returned: the reference is tokenized',
    !!result.identity?.subjectRef &&
      !result.identity.subjectRef.includes(UIN) &&
      result.identity.subjectRef.startsWith('mosip_ida:'),
    result.identity?.subjectRef,
  );
  check(
    'only the attributes MOSIP confirmed are reported',
    result.identity?.fullName === 'Amina Bello' && result.identity?.dateOfBirth === '1990/04/11',
  );

  // ---- Failing closed ------------------------------------------------------
  console.log('\n  -- failing closed');

  authStatus = false;
  authErrors = [{ errorCode: 'IDA-MLC-002', errorMessage: 'Invalid OTP' }];
  const rejected = await adapter.verify({
    countryCode: 'NG',
    identifiers: { individualId: UIN, otp: '000000' },
    challengeRef: challenge.challengeRef,
  });
  check(
    'a rejected authentication carries MOSIP\'s error code, which is the actionable part',
    !rejected.verified && rejected.reason === 'IDA_IDA-MLC-002',
    rejected.reason,
  );
  check('a rejected authentication binds nothing', !rejected.applicantBinding);
  authStatus = true;
  authErrors = [];

  const noId = await adapter.verify({ countryCode: 'NG', identifiers: {} });
  check('a missing identity number is refused before any call', !noId.verified && noId.reason === 'MISSING_INDIVIDUAL_ID');

  // Nothing to authenticate with: ask for an OTP rather than send an empty assertion.
  const nothing = await adapter.verify({ countryCode: 'NG', identifiers: { individualId: UIN } });
  check(
    'a bare identity number triggers an OTP instead of asserting nothing',
    !nothing.verified && nothing.reason === 'OTP_REQUIRED' && !!nothing.pendingChallenge,
    nothing.reason,
  );

  // Config that cannot reach MOSIP is refused at startup, not at the first resident.
  let refusedIncomplete = false;
  try {
    new MosipIdaAdapter('test-pepper').init({
      code: 'MOSIP_IDA',
      baseUrl,
      assuranceOnSuccess: 'high',
      extra: { partnerId: 'x' } as unknown as Record<string, unknown>,
    });
  } catch (e) {
    refusedIncomplete = (e as Error).message.includes('partner onboarding');
  }
  check('incomplete partner configuration is refused at init', refusedIncomplete);

  const savedKey = process.env.IDA_SIGNING_KEY;
  delete process.env.IDA_SIGNING_KEY;
  const noSigningKey = await adapter.verify({
    countryCode: 'NG',
    identifiers: { individualId: UIN, otp: OTP },
    challengeRef: challenge.challengeRef,
  });
  process.env.IDA_SIGNING_KEY = savedKey;
  check(
    'a missing signing key fails the verification rather than sending an unsigned request',
    !noSigningKey.verified,
    noSigningKey.reason,
  );

  // ---- The registry --------------------------------------------------------
  console.log('\n  -- registry');
  const registry = new ProviderRegistry('test-pepper');
  const resolved = registry.resolve(providerConfig);
  check('MOSIP_IDA resolves to the real adapter, not the generic REST fallback', resolved instanceof MosipIdaAdapter);

  server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});