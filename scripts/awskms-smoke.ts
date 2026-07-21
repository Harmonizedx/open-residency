/* eslint-disable no-console */
/**
 * AWS KMS signer test, against a mock KMS service.
 *
 * WHAT THIS PROVES: the adapter speaks the KMS JSON protocol correctly -- SigV4
 * signing, the x-amz-target actions, base64 encoding, DER-to-JWK conversion, the
 * PureEdDSA algorithm choice, the 4096-byte RAW limit, error handling -- and that
 * credentials signed through it verify.
 *
 * WHAT IT DOES NOT PROVE: that it works against real AWS KMS. IAM policy, key policies,
 * regional endpoints, and the credential chain (IRSA / task role / instance profile) are
 * all unexercised. Before relying on this in production, sign one credential against a
 * real key and verify it.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { generateKeyPairSync, sign as cryptoSign, createPublicKey, verify as cryptoVerify, KeyObject } from 'node:crypto';
import { jwtVerify, importJWK, KeyLike } from 'jose';
import { KeyStore } from '../src/core/credentials/keystore';
import { AwsKmsSigner, ed25519JwkFromDer, MAX_RAW_MESSAGE_BYTES } from '../src/core/credentials/signers/aws-kms-signer';
import { signRequest, sigv4Timestamps } from '../src/core/credentials/signers/aws-sigv4';
import { VcIssuer } from '../src/core/credentials/vc-issuer';
import { LdpIssuer, LdpCredential } from '../src/core/credentials/ldp-issuer';
import { VcVerifier, TrustedIssuer } from '../src/core/credentials/vc-verifier';
import { parseCountryConfig, CountryConfig } from '../src/core/config/country-config';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { InMemoryStore } from '../src/core/residency/ports';
import { ResidencyService } from '../src/core/residency/residency-service';
import { didKeyFromJwk } from '../src/core/credentials/did';

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

const KEY_ID = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const REGION = 'eu-west-1';
const ISSUER_DID = 'did:web:id.katsina.gov.ng';
const STATUS_URL = 'https://id.katsina.gov.ng/.well-known/status/ng.json';

const CONFIG: CountryConfig = parseCountryConfig({
  countryCode: 'NG',
  countryName: 'Nigeria',
  foundational: { provider: 'MOCK', inputs: [{ key: 'nin', label: 'NIN' }], assuranceOnSuccess: 'verified' },
  residency: { minAssurance: 'verified', proofOfResidence: 'attestation' },
  credential: {
    issuerDid: ISSUER_DID,
    issuerName: 'Katsina State Residency Authority',
    type: 'StateResidencyCredential',
    validityDays: 1095,
    context: ['https://www.w3.org/ns/credentials/v2'],
  },
  subnationalUnits: [{ code: 'KT', name: 'Katsina', parent: 'NG', level: 'state' }],
});

interface Recorded {
  target?: string;
  authorization?: string;
  amzDate?: string;
  body?: Record<string, unknown>;
}

interface Mock {
  server: Server;
  endpoint: string;
  recorded: Recorded[];
  publicKeyDer: Buffer;
  privateKey: KeyObject;
  keySpec: string;
  signingAlgorithms: string[];
  failNextWith?: number;
  /** Return a DER-wrapped signature, as KMS does for ECDSA, to prove we reject it. */
  returnDerSignature: boolean;
}

async function startMock(): Promise<Mock> {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const state: Mock = {
    server: undefined as unknown as Server,
    endpoint: '',
    recorded: [],
    publicKeyDer: publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
    privateKey,
    keySpec: 'ECC_NIST_EDWARDS25519',
    signingAlgorithms: ['ED25519_SHA_512', 'ED25519_PH_SHA_512'],
    returnDerSignature: false,
  };

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
      const target = req.headers['x-amz-target'] as string | undefined;
      state.recorded.push({
        target,
        authorization: req.headers.authorization as string | undefined,
        amzDate: req.headers['x-amz-date'] as string | undefined,
        body,
      });

      if (state.failNextWith) {
        const status = state.failNextWith;
        state.failNextWith = undefined;
        res.writeHead(status, { 'content-type': 'application/x-amz-json-1.1' });
        res.end(JSON.stringify({ __type: 'AccessDeniedException', message: 'not authorized' }));
        return;
      }

      if (target === 'TrentService.GetPublicKey') {
        res.writeHead(200, { 'content-type': 'application/x-amz-json-1.1' });
        res.end(
          JSON.stringify({
            KeyId: KEY_ID,
            PublicKey: state.publicKeyDer.toString('base64'),
            KeySpec: state.keySpec,
            KeyUsage: 'SIGN_VERIFY',
            SigningAlgorithms: state.signingAlgorithms,
          }),
        );
        return;
      }

      if (target === 'TrentService.Sign') {
        const message = Buffer.from(String(body?.Message ?? ''), 'base64');
        let signature: Buffer = cryptoSign(null, message, state.privateKey);
        if (state.returnDerSignature) {
          state.returnDerSignature = false;
          signature = Buffer.concat([Buffer.from([0x30, 0x44]), signature]);
        }
        res.writeHead(200, { 'content-type': 'application/x-amz-json-1.1' });
        res.end(
          JSON.stringify({
            KeyId: KEY_ID,
            Signature: signature.toString('base64'),
            SigningAlgorithm: body?.SigningAlgorithm,
          }),
        );
        return;
      }

      res.writeHead(400);
      res.end('{}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  state.server = server;
  state.endpoint = `http://127.0.0.1:${port}`;
  return state;
}

const CREDS = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};

async function main() {
  console.log('\n== OpenResidency AWS KMS signer test (mock service) ==\n');

  // --- SigV4 itself, against the AWS-documented test vector shape -----------
  const headers = signRequest({
    credentials: CREDS,
    region: 'us-east-1',
    service: 'kms',
    host: 'kms.us-east-1.amazonaws.com',
    target: 'TrentService.Sign',
    body: '{}',
    now: new Date(Date.UTC(2026, 6, 20, 13, 45, 1)),
  });
  check('SigV4 emits an AWS4-HMAC-SHA256 authorization', /^AWS4-HMAC-SHA256 /.test(headers.authorization));
  check('the credential scope names the region and service', /\/20260720\/us-east-1\/kms\/aws4_request/.test(headers.authorization));
  check(
    'SignedHeaders are lowercase and sorted',
    /SignedHeaders=content-type;host;x-amz-date;x-amz-target/.test(headers.authorization),
  );
  check('x-amz-date matches the signed timestamp', headers['x-amz-date'] === '20260720T134501Z');
  const withSession = signRequest({
    credentials: { ...CREDS, sessionToken: 'session-token' },
    region: 'us-east-1', service: 'kms', host: 'kms.us-east-1.amazonaws.com',
    target: 'TrentService.Sign', body: '{}',
  });
  check(
    'a session token is sent AND covered by the signature',
    withSession['x-amz-security-token'] === 'session-token' &&
      /SignedHeaders=[^,]*x-amz-security-token/.test(withSession.authorization),
  );
  const ts = sigv4Timestamps(new Date(Date.UTC(2026, 0, 2, 3, 4, 5)));
  check('timestamps are formatted as SigV4 expects', ts.amzDate === '20260102T030405Z' && ts.dateStamp === '20260102');

  // --- Protocol: GetPublicKey -----------------------------------------------
  const mock = await startMock();
  const signer = await AwsKmsSigner.open({
    keyId: KEY_ID,
    region: REGION,
    kid: 'aws-key-1',
    endpoint: mock.endpoint,
    credentials: async () => CREDS,
  });

  const getCall = mock.recorded[0];
  check('the public key is fetched with TrentService.GetPublicKey', getCall.target === 'TrentService.GetPublicKey');
  check('the request is SigV4-signed', /^AWS4-HMAC-SHA256 /.test(getCall.authorization ?? ''));
  check('the key id is sent', getCall.body?.KeyId === KEY_ID);
  check('the DER public key is converted to an Ed25519 JWK', signer.publicJwk.crv === 'Ed25519');
  check('the JWK carries no private material', !('d' in signer.publicJwk));
  check('the signer publishes the configured kid', signer.kid === 'aws-key-1');
  check(
    'the derived public key matches the service DER',
    signer.publicJwk.x === ed25519JwkFromDer(mock.publicKeyDer, 'aws-key-1').x,
  );

  // --- Protocol: Sign --------------------------------------------------------
  const message = Buffer.from('the quick brown fox');
  const signature = await signer.sign(message);
  const signCall = mock.recorded[1];
  check('sign uses TrentService.Sign', signCall.target === 'TrentService.Sign');
  check(
    'the full message is sent as base64 Message',
    Buffer.from(String(signCall.body?.Message), 'base64').equals(message),
  );
  check('MessageType is RAW (PureEdDSA, what JWS EdDSA means)', signCall.body?.MessageType === 'RAW');
  check(
    'SigningAlgorithm is ED25519_SHA_512, never the _PH_ HashEdDSA variant',
    signCall.body?.SigningAlgorithm === 'ED25519_SHA_512',
  );
  check('the returned signature is 64 raw bytes', signature.length === 64);

  const pubKeyObject = createPublicKey({ key: mock.publicKeyDer, format: 'der', type: 'spki' });
  check(
    'node:crypto verifies the signature the service produced',
    cryptoVerify(null, message, pubKeyObject, signature),
  );

  // --- The guards -----------------------------------------------------------
  let overSize = '';
  try {
    await signer.sign(Buffer.alloc(MAX_RAW_MESSAGE_BYTES + 1));
  } catch (e) {
    overSize = (e as Error).message;
  }
  check(
    'a message over 4096 bytes is refused with an explanation',
    /4096/.test(overSize) && /pre-hash/.test(overSize),
  );

  mock.returnDerSignature = true;
  let derCaught = '';
  try {
    await signer.sign(Buffer.from('payload'));
  } catch (e) {
    derCaught = (e as Error).message;
  }
  check('a non-64-byte (DER-shaped) signature is rejected', /64-byte/.test(derCaught));

  mock.failNextWith = 400;
  let httpCaught = '';
  try {
    await signer.sign(Buffer.from('payload'));
  } catch (e) {
    httpCaught = (e as Error).message;
  }
  check('an API failure surfaces the status and the needed permission', /400/.test(httpCaught) && /kms:Sign/.test(httpCaught));

  // A wrong key spec must be refused at open, not at first signature.
  const savedSpec = mock.keySpec;
  mock.keySpec = 'ECC_NIST_P256';
  let specCaught = '';
  try {
    await AwsKmsSigner.open({ keyId: KEY_ID, region: REGION, endpoint: mock.endpoint, credentials: async () => CREDS });
  } catch (e) {
    specCaught = (e as Error).message;
  }
  mock.keySpec = savedSpec;
  check('a non-Ed25519 key spec is refused when the signer opens', /ECC_NIST_EDWARDS25519/.test(specCaught));

  const savedAlgs = mock.signingAlgorithms;
  mock.signingAlgorithms = ['ED25519_PH_SHA_512'];
  let algCaught = '';
  try {
    await AwsKmsSigner.open({ keyId: KEY_ID, region: REGION, endpoint: mock.endpoint, credentials: async () => CREDS });
  } catch (e) {
    algCaught = (e as Error).message;
  }
  mock.signingAlgorithms = savedAlgs;
  check('a key offering only HashEdDSA is refused', /PureEdDSA/.test(algCaught));

  // --- End-to-end issuance through AWS KMS ----------------------------------
  const key = await KeyStore.fromSigner(signer);
  check('the issuer key carries no exportable private key', key.privateKey === undefined);

  const residents = new InMemoryStore();
  const residency = new ResidencyService(
    new ProviderRegistry('aws-test-pepper'),
    new VcIssuer(key),
    residents,
    () => STATUS_URL,
    new LdpIssuer(key),
  );
  const enrolled = await residency.issue(CONFIG, {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    identifiers: { nin: '12345678902' },
  });
  check('a resident is enrolled and issued via AWS KMS', enrolled.status === 'issued');
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const record = (await residents.findByResidentId(enrolled.residentId))!;

  const holderDid = didKeyFromJwk((await KeyStore.generate('holder')).publicJwk);
  const jwt = (await residency.mintForHolder(CONFIG, record, holderDid, 'jwt_vc_json'))
    .credential as string;

  // The real reason the 4096-byte cap matters: confirm our actual signing input fits.
  const signingInput = jwt.split('.').slice(0, 2).join('.');
  check(
    `the real VC-JWT signing input fits AWS's RAW cap (${Buffer.byteLength(signingInput)} of ${MAX_RAW_MESSAGE_BYTES} bytes)`,
    Buffer.byteLength(signingInput) < MAX_RAW_MESSAGE_BYTES,
  );

  const verifyKey = (await importJWK(key.publicJwk, 'EdDSA')) as KeyLike;
  let verified = false;
  try {
    await jwtVerify(jwt, verifyKey, { issuer: ISSUER_DID });
    verified = true;
  } catch {
    verified = false;
  }
  check('a KMS-signed VC-JWT verifies against the published public key', verified);

  const trust = new Map<string, TrustedIssuer>([
    [ISSUER_DID, { did: ISSUER_DID, publicJwks: [key.publicJwk], statusLists: {} }],
  ]);
  check(
    'the standard verifier accepts the KMS-issued credential',
    (await new VcVerifier(trust).verify(jwt, { offline: true })).valid,
  );
  check(
    'a tampered KMS-issued credential is rejected',
    !(await new VcVerifier(trust).verify(jwt.slice(0, -6) + 'AAAAAA', { offline: true })).valid,
  );

  const ldp = (await residency.mintForHolder(CONFIG, record, holderDid, 'ldp_vc'))
    .credential as LdpCredential;
  check('a Data Integrity proof is produced via AWS KMS', !!ldp.proof?.proofValue);
  check('the KMS-signed Data Integrity proof verifies', await LdpIssuer.verify(ldp, pubKeyObject));

  mock.server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==`);
  console.log('   (mock service: proves protocol + issuance, NOT real AWS IAM/endpoints)\n');
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});