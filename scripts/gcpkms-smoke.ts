/* eslint-disable no-console */
/**
 * Google Cloud KMS signer test, against a mock Cloud KMS service.
 *
 * WHAT THIS PROVES: the adapter speaks the Cloud KMS REST protocol correctly -- request
 * shape, auth header, base64 encoding, CRC32C integrity checks, PEM-to-JWK conversion,
 * error handling -- and that credentials signed through it verify.
 *
 * WHAT IT DOES NOT PROVE: that it works against real Cloud KMS. IAM roles, regional
 * endpoints, quotas, and Application Default Credentials are all unexercised here. Before
 * relying on this in production, run one real signature against a real key version and
 * confirm the credential verifies. The mock is the fast check that the wire format is
 * right; it is not a substitute for touching the real service once.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { generateKeyPairSync, sign as cryptoSign, createPublicKey, KeyObject } from 'node:crypto';
import { jwtVerify, importJWK, KeyLike } from 'jose';
import { KeyStore } from '../src/core/credentials/keystore';
import { GcpKmsSigner, crc32c, ed25519JwkFromPem } from '../src/core/credentials/signers/gcp-kms-signer';
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

const KEY_NAME =
  'projects/demo/locations/global/keyRings/residency/cryptoKeys/issuer/cryptoKeyVersions/1';
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

/** What the mock recorded, so the test can assert on the wire format. */
interface Recorded {
  authorization?: string;
  method?: string;
  path?: string;
  body?: Record<string, unknown>;
}

interface Mock {
  server: Server;
  baseUrl: string;
  recorded: Recorded[];
  publicKeyPem: string;
  privateKey: KeyObject;
  /** Corrupt the next signature, to exercise the CRC32C check. */
  corruptNextSignature: boolean;
  /** Fail the next request with this status, to exercise error handling. */
  failNextWith?: number;
  /** Claim we could not verify the request checksum. */
  claimBadDataCrc: boolean;
}

async function startMock(): Promise<Mock> {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  const state: Mock = {
    server: undefined as unknown as Server,
    baseUrl: '',
    recorded: [],
    publicKeyPem,
    privateKey,
    corruptNextSignature: false,
    claimBadDataCrc: false,
  };

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
      state.recorded.push({
        authorization: req.headers.authorization,
        method: req.method,
        path: req.url,
        body,
      });

      if (state.failNextWith) {
        const status = state.failNextWith;
        state.failNextWith = undefined;
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'permission denied on resource' } }));
        return;
      }

      if (req.url?.endsWith('/publicKey')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ pem: state.publicKeyPem, algorithm: 'EC_SIGN_ED25519' }));
        return;
      }

      if (req.url?.endsWith(':asymmetricSign')) {
        const data = Buffer.from(String(body?.data ?? ''), 'base64');
        let signature = cryptoSign(null, data, state.privateKey);
        if (state.corruptNextSignature) {
          state.corruptNextSignature = false;
          signature = Buffer.from(signature);
          signature[0] ^= 0xff;
          // Report the CRC of the ORIGINAL, so the client's check must catch the flip.
          const good = cryptoSign(null, data, state.privateKey);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(
            JSON.stringify({
              signature: signature.toString('base64'),
              signatureCrc32c: String(crc32c(good)),
              verifiedDataCrc32c: true,
            }),
          );
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            signature: signature.toString('base64'),
            signatureCrc32c: String(crc32c(signature)),
            verifiedDataCrc32c: !state.claimBadDataCrc,
          }),
        );
        return;
      }

      res.writeHead(404);
      res.end('{}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  state.server = server;
  state.baseUrl = `http://127.0.0.1:${port}/v1`;
  return state;
}

async function main() {
  console.log('\n== OpenResidency Google Cloud KMS signer test (mock service) ==\n');

  const mock = await startMock();
  const signer = await GcpKmsSigner.open({
    keyName: KEY_NAME,
    kid: 'kms-key-1',
    baseUrl: mock.baseUrl,
    accessToken: async () => 'test-token',
  });

  // --- Protocol: the public key fetch ---------------------------------------
  const fetchCall = mock.recorded[0];
  check('the public key is fetched from the key version resource', fetchCall.path === `/v1/${KEY_NAME}/publicKey`);
  check('the request carries a bearer token', fetchCall.authorization === 'Bearer test-token');
  check('the PEM is converted to an Ed25519 JWK', signer.publicJwk.crv === 'Ed25519');
  check('the JWK carries no private material', !('d' in signer.publicJwk));
  check('the signer publishes the configured kid', signer.kid === 'kms-key-1');
  check('the signer advertises EdDSA', signer.alg === 'EdDSA');

  const expectedJwk = ed25519JwkFromPem(mock.publicKeyPem, 'kms-key-1');
  check('the derived public key matches the service PEM', signer.publicJwk.x === expectedJwk.x);

  // --- Protocol: signing ----------------------------------------------------
  const message = Buffer.from('the quick brown fox');
  const signature = await signer.sign(message);
  const signCall = mock.recorded[1];
  check('sign POSTs to :asymmetricSign', signCall.path === `/v1/${KEY_NAME}:asymmetricSign` && signCall.method === 'POST');
  check(
    'the full message is sent as base64 `data` (not a digest)',
    Buffer.from(String(signCall.body?.data), 'base64').equals(message),
  );
  check('a dataCrc32c is sent for integrity', String(signCall.body?.dataCrc32c) === String(crc32c(message)));
  check('the returned signature is 64 raw bytes', signature.length === 64);

  const pubKeyObject = createPublicKey(mock.publicKeyPem);
  check(
    'node:crypto verifies the signature the service produced',
    require('node:crypto').verify(null, message, pubKeyObject, signature),
  );

  // --- Integrity and error handling -----------------------------------------
  mock.corruptNextSignature = true;
  let crcCaught = '';
  try {
    await signer.sign(Buffer.from('payload'));
  } catch (e) {
    crcCaught = (e as Error).message;
  }
  check('a corrupted signature is caught by the CRC32C check', /CRC32C/.test(crcCaught));

  mock.claimBadDataCrc = true;
  let dataCrcCaught = '';
  try {
    await signer.sign(Buffer.from('payload'));
  } catch (e) {
    dataCrcCaught = (e as Error).message;
  }
  mock.claimBadDataCrc = false;
  check('a request-corruption report from KMS is surfaced', /corrupted/.test(dataCrcCaught));

  mock.failNextWith = 403;
  let httpCaught = '';
  try {
    await signer.sign(Buffer.from('payload'));
  } catch (e) {
    httpCaught = (e as Error).message;
  }
  check('an HTTP failure surfaces the status and a directed hint', /403/.test(httpCaught) && /cloudkms\.signer/.test(httpCaught));

  // A wrong-algorithm key must be refused up front, not at first signature.
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPem = rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const savedPem = mock.publicKeyPem;
  mock.publicKeyPem = rsaPem;
  let algCaught = '';
  try {
    await GcpKmsSigner.open({
      keyName: KEY_NAME,
      baseUrl: mock.baseUrl,
      accessToken: async () => 'test-token',
    });
  } catch (e) {
    algCaught = (e as Error).message;
  }
  mock.publicKeyPem = savedPem;
  check('a non-Ed25519 key is refused when the signer opens', /EC_SIGN_ED25519|Ed25519/.test(algCaught));

  // --- End-to-end issuance through Cloud KMS --------------------------------
  const key = await KeyStore.fromSigner(signer);
  check('the issuer key carries no exportable private key', key.privateKey === undefined);

  const residents = new InMemoryStore();
  const residency = new ResidencyService(
    new ProviderRegistry('kms-test-pepper'),
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
  check('a resident is enrolled and issued via Cloud KMS', enrolled.status === 'issued');
  if (enrolled.status !== 'issued') throw new Error('enrollment failed');
  const record = (await residents.findByResidentId(enrolled.residentId))!;

  const holderKey = await KeyStore.generate('holder');
  const holderDid = didKeyFromJwk(holderKey.publicJwk);

  const jwt = (await residency.mintForHolder(CONFIG, record, holderDid, 'jwt_vc_json'))
    .credential as string;
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
  check('a Data Integrity proof is produced via Cloud KMS', !!ldp.proof?.proofValue);
  check('the KMS-signed Data Integrity proof verifies', await LdpIssuer.verify(ldp, pubKeyObject));

  mock.server.close();
  console.log(`\n== ${pass} passed, ${fail} failed ==`);
  console.log('   (mock service: proves protocol + issuance, NOT real GCP IAM/endpoints)\n');
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
