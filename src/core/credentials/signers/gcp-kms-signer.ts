import { createPublicKey, createSign } from 'node:crypto';
import { JWK, base64url } from 'jose';
import { Signer, SignatureAlg } from '../signer';

/**
 * Google Cloud KMS signer: the issuer key lives in Cloud KMS (or Cloud HSM) and signing
 * happens through the API, so the private key never enters this process.
 *
 * Cloud KMS offers Ed25519 as `EC_SIGN_ED25519` ("EdDSA on Curve25519 in PureEdDSA
 * mode, which takes raw data as input instead of hashed data"), which is exactly what
 * this codebase needs end to end -- `did.ts` resolves only Ed25519 multicodecs, the Data
 * Integrity cryptosuite is `eddsa-rdfc-2022`, and JWS `EdDSA` means PureEdDSA.
 *
 * AWS KMS also supports Ed25519 (key spec `ECC_NIST_EDWARDS25519`, signing algorithm
 * `ED25519_SHA_512` with `MessageType: RAW`) since November 2025, so an AWS adapter is
 * equally possible; it is simply not written yet. Note that AWS caps the `Sign` message
 * at 4096 bytes in RAW mode -- fine here, since our largest signing input is the VC-JWT
 * at roughly 2 KB -- and that its `ED25519_PH_SHA_512` variant is HashEdDSA, a DIFFERENT
 * algorithm whose signatures standard Ed25519 verifiers reject. An AWS adapter must use
 * `ED25519_SHA_512`/RAW.
 *
 * Deliberately built on `fetch` and the REST API rather than `@google-cloud/kms`: the
 * SDK pulls in a large gRPC dependency tree for two calls, and this keeps the adapter
 * a dependency-free file that a deployment can audit in one sitting.
 *
 * Set `CLOUD_KMS_PROTECTION_LEVEL=HSM` on the key in GCP for hardware custody. The
 * adapter behaves identically either way -- that is a property of the key, not of this
 * code -- but the custody guarantee is only as strong as the key's protection level.
 */

const KMS_SCOPE = 'https://www.googleapis.com/auth/cloudkms';
const DEFAULT_BASE_URL = 'https://cloudkms.googleapis.com/v1';
const METADATA_TOKEN_URL =
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';
const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';

export interface GcpKmsConfig {
  /**
   * The full crypto key VERSION resource name:
   *   projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
   *
   * A version, not a key: signing is always done by a specific version, and pinning it
   * here is what makes rotation an explicit, staged operation rather than something that
   * silently changes which key signed a credential.
   */
  keyName: string;
  /** The `kid` this key is published under. Defaults to the key version resource id. */
  kid?: string;
  /** Override for testing, or for a private service endpoint. */
  baseUrl?: string;
  /** Supply an OAuth access token. Defaults to ADC (service account key, else metadata). */
  accessToken?: () => Promise<string>;
  /** Injected for testing. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * CRC32C over a buffer (Castagnoli polynomial, reflected).
 *
 * Cloud KMS returns a CRC32C alongside every signature and asks callers to check it.
 * It is worth doing: without it a corrupted response becomes a signature that simply
 * fails to verify later, somewhere else, with no indication that the transport was at
 * fault rather than the key.
 */
const CRC32C_TABLE: number[] = (() => {
  const table = new Array<number>(256);
  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
    table[i] = crc >>> 0;
  }
  return table;
})();

export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ data[i]) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

/** Convert the PEM Cloud KMS returns for a public key into an Ed25519 JWK. */
export function ed25519JwkFromPem(pem: string, kid: string): JWK {
  const key = createPublicKey(pem);
  const jwk = key.export({ format: 'jwk' }) as JWK;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new Error(
      `the Cloud KMS key is ${jwk.kty}/${jwk.crv ?? '?'}, not OKP/Ed25519. This deployment ` +
        'issues Ed25519 credentials only; create the key with algorithm EC_SIGN_ED25519.',
    );
  }
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid };
}

export class GcpKmsSigner implements Signer {
  readonly alg: SignatureAlg = 'EdDSA';

  private constructor(
    readonly kid: string,
    readonly publicJwk: JWK,
    private readonly cfg: Required<Pick<GcpKmsConfig, 'keyName' | 'baseUrl'>> & GcpKmsConfig,
    private readonly getToken: () => Promise<string>,
    private readonly doFetch: typeof fetch,
  ) {}

  /** Resolve the key's public half and return a ready signer. */
  static async open(cfg: GcpKmsConfig): Promise<GcpKmsSigner> {
    const baseUrl = cfg.baseUrl ?? DEFAULT_BASE_URL;
    const doFetch = cfg.fetchImpl ?? fetch;
    const getToken = cfg.accessToken ?? defaultTokenProvider(doFetch);
    const kid = cfg.kid ?? cfg.keyName.split('/').pop() ?? 'kms-key-1';

    const token = await getToken();
    const res = await doFetch(`${baseUrl}/${cfg.keyName}/publicKey`, {
      headers: { authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(
        `Cloud KMS publicKey failed (${res.status}): ${await safeText(res)}. Check that the ` +
          'key version exists and the service account has roles/cloudkms.viewer.',
      );
    }
    const body = (await res.json()) as { pem?: string; algorithm?: string };
    if (!body.pem) throw new Error('Cloud KMS publicKey returned no PEM.');
    if (body.algorithm && body.algorithm !== 'EC_SIGN_ED25519') {
      throw new Error(
        `the Cloud KMS key algorithm is ${body.algorithm}, not EC_SIGN_ED25519. This ` +
          'deployment issues Ed25519 credentials only.',
      );
    }

    return new GcpKmsSigner(
      kid,
      ed25519JwkFromPem(body.pem, kid),
      { ...cfg, keyName: cfg.keyName, baseUrl },
      getToken,
      doFetch,
    );
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const token = await this.getToken();
    const res = await this.doFetch(`${this.cfg.baseUrl}/${this.cfg.keyName}:asymmetricSign`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      // Ed25519 signs the message itself, so the full signing input goes in `data`.
      // Cloud KMS caps this at 64 KiB, which every token and credential here is far under.
      body: JSON.stringify({
        data: Buffer.from(data).toString('base64'),
        dataCrc32c: String(crc32c(data)),
      }),
    });
    if (!res.ok) {
      throw new Error(
        `Cloud KMS asymmetricSign failed (${res.status}): ${await safeText(res)}. Check that ` +
          'the service account has roles/cloudkms.signer on this key.',
      );
    }

    const body = (await res.json()) as {
      signature?: string;
      signatureCrc32c?: string;
      verifiedDataCrc32c?: boolean;
    };
    if (!body.signature) throw new Error('Cloud KMS asymmetricSign returned no signature.');

    // If KMS reports it did not verify our request checksum, the request was corrupted
    // in transit and it signed something other than what we sent.
    if (body.verifiedDataCrc32c === false) {
      throw new Error('Cloud KMS reported a data CRC32C mismatch: the request was corrupted.');
    }

    const signature = Buffer.from(body.signature, 'base64');
    if (body.signatureCrc32c && crc32c(signature) !== Number(body.signatureCrc32c)) {
      throw new Error('Cloud KMS signature failed its CRC32C check: the response was corrupted.');
    }
    // Ed25519 signatures are raw 64-byte values, which is the JWS form directly.
    if (signature.length !== 64) {
      throw new Error(`expected a 64-byte Ed25519 signature, got ${signature.length} bytes.`);
    }
    return new Uint8Array(signature);
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 300);
  } catch {
    return '<no body>';
  }
}

/**
 * Application Default Credentials, narrowed to what this adapter needs.
 *
 * A service account key file if GOOGLE_APPLICATION_CREDENTIALS points at one, otherwise
 * the GCE/GKE metadata server -- which is the path a workload-identity deployment takes
 * and the one that involves no key file at all.
 */
export function defaultTokenProvider(doFetch: typeof fetch = fetch): () => Promise<string> {
  let cached: { token: string; expiresAt: number } | undefined;

  return async () => {
    // Refresh a minute early rather than racing the expiry.
    if (cached && Date.now() < cached.expiresAt - 60_000) return cached.token;

    const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const fetched = keyFile
      ? await tokenFromServiceAccountKey(keyFile, doFetch)
      : await tokenFromMetadataServer(doFetch);

    cached = { token: fetched.token, expiresAt: Date.now() + fetched.expiresIn * 1000 };
    return cached.token;
  };
}

async function tokenFromMetadataServer(
  doFetch: typeof fetch,
): Promise<{ token: string; expiresIn: number }> {
  const res = await doFetch(METADATA_TOKEN_URL, { headers: { 'Metadata-Flavor': 'Google' } });
  if (!res.ok) {
    throw new Error(
      `could not get a token from the GCE metadata server (${res.status}). Outside GCP, set ` +
        'GOOGLE_APPLICATION_CREDENTIALS to a service account key file.',
    );
  }
  const body = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!body.access_token) throw new Error('the metadata server returned no access_token.');
  return { token: body.access_token, expiresIn: body.expires_in ?? 3600 };
}

/** The self-signed-JWT flow: sign an assertion with the key file, exchange it for a token. */
async function tokenFromServiceAccountKey(
  keyFile: string,
  doFetch: typeof fetch,
): Promise<{ token: string; expiresIn: number }> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { readFileSync } = require('node:fs');
  let creds: { client_email?: string; private_key?: string };
  try {
    creds = JSON.parse(readFileSync(keyFile, 'utf8'));
  } catch (e) {
    throw new Error(`could not read GOOGLE_APPLICATION_CREDENTIALS at ${keyFile}: ${(e as Error).message}`);
  }
  if (!creds.client_email || !creds.private_key) {
    throw new Error(`${keyFile} is not a service account key (no client_email/private_key).`);
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64url.encode(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claims = base64url.encode(
    Buffer.from(
      JSON.stringify({
        iss: creds.client_email,
        scope: KMS_SCOPE,
        aud: OAUTH_TOKEN_URL,
        iat: now,
        exp: now + 3600,
      }),
    ),
  );
  const signingInput = `${header}.${claims}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  const assertion = `${signingInput}.${base64url.encode(signer.sign(creds.private_key))}`;

  const res = await doFetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  });
  if (!res.ok) {
    throw new Error(`the OAuth token exchange failed (${res.status}): ${await safeText(res)}`);
  }
  const body = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!body.access_token) throw new Error('the OAuth token exchange returned no access_token.');
  return { token: body.access_token, expiresIn: body.expires_in ?? 3600 };
}
