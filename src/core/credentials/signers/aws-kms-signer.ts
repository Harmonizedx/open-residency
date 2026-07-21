import { createPublicKey } from 'node:crypto';
import { JWK } from 'jose';
import { Signer, SignatureAlg } from '../signer';
import { AwsCredentials, signRequest } from './aws-sigv4';

/**
 * AWS KMS signer: the issuer key lives in KMS and signing happens through the API, so
 * the private key never enters this process.
 *
 * KMS gained Ed25519 in November 2025 -- key spec `ECC_NIST_EDWARDS25519`, signing
 * algorithm `ED25519_SHA_512` -- which is what makes this adapter possible at all, since
 * the credential format is Ed25519 end to end.
 *
 * TWO THINGS HERE ARE EASY TO GET WRONG AND FAIL SILENTLY LATER:
 *
 * 1. ALGORITHM. KMS offers two Ed25519 signing algorithms and they are not
 *    interchangeable. `ED25519_SHA_512` (with `MessageType: RAW`) is PureEdDSA -- the
 *    algorithm JWS `EdDSA` and the `eddsa-rdfc-2022` cryptosuite both mean.
 *    `ED25519_PH_SHA_512` (with `MessageType: DIGEST`) is HashEdDSA/Ed25519ph, a
 *    DIFFERENT algorithm whose signatures every standard Ed25519 verifier rejects. The
 *    second one looks like the natural way to dodge the message size limit below, and
 *    taking it would produce credentials that pass our own round-trip tests and fail in
 *    every wallet. This adapter uses RAW/PureEdDSA and refuses anything else.
 *
 * 2. MESSAGE SIZE. KMS caps `Sign` at 4096 bytes in RAW mode, and PureEdDSA cannot
 *    pre-hash, so that cap is hard. Our largest signing input is the VC-JWT at roughly
 *    2 KB, comfortably under -- but a deployment that adds many claims could cross it,
 *    so the limit is checked here with a message that explains the constraint rather
 *    than surfacing an opaque AWS validation error.
 */

const SIGNING_ALGORITHM = 'ED25519_SHA_512';
const KEY_SPEC = 'ECC_NIST_EDWARDS25519';
/** KMS `Sign` accepts at most 4096 bytes when MessageType is RAW. */
export const MAX_RAW_MESSAGE_BYTES = 4096;

export interface AwsKmsConfig {
  /** Key id, ARN, alias name, or alias ARN. An ARN is clearest across accounts. */
  keyId: string;
  region: string;
  /** The `kid` this key is published under. Defaults to the key id's last path segment. */
  kid?: string;
  /** Override for testing, VPC endpoints, or FIPS endpoints. */
  endpoint?: string;
  /** Supply credentials. Defaults to the standard chain (env, IRSA, container, IMDSv2). */
  credentials?: () => Promise<AwsCredentials>;
  /** Injected for testing. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export class AwsKmsSigner implements Signer {
  readonly alg: SignatureAlg = 'EdDSA';

  private constructor(
    readonly kid: string,
    readonly publicJwk: JWK,
    private readonly cfg: AwsKmsConfig & { endpoint: string },
    private readonly getCredentials: () => Promise<AwsCredentials>,
    private readonly doFetch: typeof fetch,
  ) {}

  /** Fetch the key's public half and verify it is an Ed25519 signing key. */
  static async open(cfg: AwsKmsConfig): Promise<AwsKmsSigner> {
    const endpoint = cfg.endpoint ?? `https://kms.${cfg.region}.amazonaws.com`;
    const doFetch = cfg.fetchImpl ?? fetch;
    const getCredentials = cfg.credentials ?? defaultCredentialProvider(doFetch);
    const kid = cfg.kid ?? cfg.keyId.split('/').pop() ?? 'kms-key-1';

    const body = await call<{
      PublicKey?: string;
      KeySpec?: string;
      KeyUsage?: string;
      SigningAlgorithms?: string[];
    }>(
      { ...cfg, endpoint },
      getCredentials,
      doFetch,
      'TrentService.GetPublicKey',
      { KeyId: cfg.keyId },
      'GetPublicKey',
      'kms:GetPublicKey',
    );

    if (!body.PublicKey) throw new Error('AWS KMS GetPublicKey returned no PublicKey.');
    if (body.KeySpec && body.KeySpec !== KEY_SPEC) {
      throw new Error(
        `the KMS key spec is ${body.KeySpec}, not ${KEY_SPEC}. This deployment issues ` +
          'Ed25519 credentials only; create the key with the Ed25519 key spec.',
      );
    }
    if (body.KeyUsage && body.KeyUsage !== 'SIGN_VERIFY') {
      throw new Error(`the KMS key usage is ${body.KeyUsage}, not SIGN_VERIFY.`);
    }
    if (body.SigningAlgorithms && !body.SigningAlgorithms.includes(SIGNING_ALGORITHM)) {
      throw new Error(
        `the KMS key does not support ${SIGNING_ALGORITHM} (it offers ` +
          `${body.SigningAlgorithms.join(', ')}). PureEdDSA is required.`,
      );
    }

    // GetPublicKey returns DER (SPKI), base64-encoded.
    const der = Buffer.from(body.PublicKey, 'base64');
    const publicJwk = ed25519JwkFromDer(der, kid);

    return new AwsKmsSigner(kid, publicJwk, { ...cfg, endpoint }, getCredentials, doFetch);
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    if (data.length > MAX_RAW_MESSAGE_BYTES) {
      throw new Error(
        `signing input is ${data.length} bytes; AWS KMS accepts at most ` +
          `${MAX_RAW_MESSAGE_BYTES} with MessageType RAW. PureEdDSA cannot pre-hash, so ` +
          'this limit is hard -- reduce the credential payload, or move to a backend ' +
          'without a message cap (pkcs11, gcpkms).',
      );
    }

    const body = await call<{ Signature?: string; SigningAlgorithm?: string }>(
      this.cfg as AwsKmsConfig & { endpoint: string },
      this.getCredentials,
      this.doFetch,
      'TrentService.Sign',
      {
        KeyId: this.cfg.keyId,
        Message: Buffer.from(data).toString('base64'),
        // RAW, never DIGEST: DIGEST would select HashEdDSA and produce signatures that
        // standard Ed25519 verifiers reject. See the note at the top of this file.
        MessageType: 'RAW',
        SigningAlgorithm: SIGNING_ALGORITHM,
      },
      'Sign',
      'kms:Sign',
    );

    if (!body.Signature) throw new Error('AWS KMS Sign returned no Signature.');
    if (body.SigningAlgorithm && body.SigningAlgorithm !== SIGNING_ALGORITHM) {
      throw new Error(
        `AWS KMS signed with ${body.SigningAlgorithm}, not ${SIGNING_ALGORITHM}. Refusing ` +
          'the signature: it would not verify as EdDSA.',
      );
    }

    const signature = Buffer.from(body.Signature, 'base64');
    // Ed25519 signatures are raw 64-byte values -- unlike ECDSA, which KMS returns DER
    // encoded. A different length means we are not getting PureEdDSA.
    if (signature.length !== 64) {
      throw new Error(
        `expected a 64-byte Ed25519 signature, got ${signature.length} bytes. The key may ` +
          'not be an Ed25519 key.',
      );
    }
    return new Uint8Array(signature);
  }
}

/** Convert the DER (SPKI) public key KMS returns into an Ed25519 JWK. */
export function ed25519JwkFromDer(der: Buffer, kid: string): JWK {
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' }) as JWK;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new Error(
      `the KMS public key is ${jwk.kty}/${jwk.crv ?? '?'}, not OKP/Ed25519.`,
    );
  }
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid };
}

async function call<T>(
  cfg: AwsKmsConfig & { endpoint: string },
  getCredentials: () => Promise<AwsCredentials>,
  doFetch: typeof fetch,
  target: string,
  payload: Record<string, unknown>,
  operation: string,
  permission: string,
): Promise<T> {
  const body = JSON.stringify(payload);
  const host = new URL(cfg.endpoint).host;
  const headers = signRequest({
    credentials: await getCredentials(),
    region: cfg.region,
    service: 'kms',
    host,
    target,
    body,
  });

  const res = await doFetch(cfg.endpoint, { method: 'POST', headers, body });
  if (!res.ok) {
    const text = await res.text().catch(() => '<no body>');
    throw new Error(
      `AWS KMS ${operation} failed (${res.status}): ${text.slice(0, 300)}. Check that the ` +
        `key exists in ${cfg.region} and that the caller has ${permission}.`,
    );
  }
  return (await res.json()) as T;
}

/**
 * The standard AWS credential chain, narrowed to what this adapter needs:
 * static environment variables, then IRSA (EKS web identity), then the container
 * credentials endpoint (ECS/EKS), then IMDSv2 (EC2 instance profile).
 *
 * Credentials are cached until shortly before they expire; static env credentials never
 * expire and are returned directly.
 */
export function defaultCredentialProvider(
  doFetch: typeof fetch = fetch,
): () => Promise<AwsCredentials> {
  let cached: { creds: AwsCredentials; expiresAt: number } | undefined;

  return async () => {
    if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
      return {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        sessionToken: process.env.AWS_SESSION_TOKEN,
      };
    }

    // Refresh a minute early rather than racing the expiry.
    if (cached && Date.now() < cached.expiresAt - 60_000) return cached.creds;

    const resolved =
      (await fromWebIdentity(doFetch)) ??
      (await fromContainerEndpoint(doFetch)) ??
      (await fromImds(doFetch));

    if (!resolved) {
      throw new Error(
        'no AWS credentials found. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or run ' +
          'with an IRSA service account, an ECS task role, or an EC2 instance profile.',
      );
    }
    cached = resolved;
    return resolved.creds;
  };
}

interface Resolved {
  creds: AwsCredentials;
  expiresAt: number;
}

/** EKS IAM Roles for Service Accounts: exchange a projected token via STS. */
async function fromWebIdentity(doFetch: typeof fetch): Promise<Resolved | undefined> {
  const tokenFile = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
  const roleArn = process.env.AWS_ROLE_ARN;
  if (!tokenFile || !roleArn) return undefined;

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { readFileSync } = require('node:fs');
  const token = readFileSync(tokenFile, 'utf8').trim();
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const url =
    `https://sts.${region}.amazonaws.com/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15` +
    `&RoleArn=${encodeURIComponent(roleArn)}` +
    `&RoleSessionName=${encodeURIComponent(process.env.AWS_ROLE_SESSION_NAME ?? 'openresidency')}` +
    `&WebIdentityToken=${encodeURIComponent(token)}`;

  const res = await doFetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(
      `STS AssumeRoleWithWebIdentity failed (${res.status}). Check AWS_ROLE_ARN and the ` +
        'service account annotation.',
    );
  }
  // STS returns XML by default. Extract the three fields rather than pulling in a parser.
  const xml = await res.text();
  const pick = (tag: string): string | undefined =>
    new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml)?.[1];

  const accessKeyId = pick('AccessKeyId');
  const secretAccessKey = pick('SecretAccessKey');
  const sessionToken = pick('SessionToken');
  const expiration = pick('Expiration');
  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    throw new Error('STS AssumeRoleWithWebIdentity returned no usable credentials.');
  }
  return {
    creds: { accessKeyId, secretAccessKey, sessionToken },
    expiresAt: expiration ? Date.parse(expiration) : Date.now() + 3600_000,
  };
}

/** ECS task roles and the EKS pod identity agent. */
async function fromContainerEndpoint(doFetch: typeof fetch): Promise<Resolved | undefined> {
  const relative = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
  const full = process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI;
  if (!relative && !full) return undefined;

  const url = full ?? `http://169.254.170.2${relative}`;
  const headers: Record<string, string> = {};
  const authToken = process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN;
  if (authToken) headers.authorization = authToken;

  const res = await doFetch(url, { headers });
  if (!res.ok) return undefined;
  return toResolved(await res.json());
}

/** EC2 instance profile, IMDSv2 (token-required) only. */
async function fromImds(doFetch: typeof fetch): Promise<Resolved | undefined> {
  const base = 'http://169.254.169.254';
  try {
    const tokenRes = await doFetch(`${base}/latest/api/token`, {
      method: 'PUT',
      headers: { 'x-aws-ec2-metadata-token-ttl-seconds': '300' },
    });
    if (!tokenRes.ok) return undefined;
    const token = await tokenRes.text();
    const h = { 'x-aws-ec2-metadata-token': token };

    const roleRes = await doFetch(`${base}/latest/meta-data/iam/security-credentials/`, { headers: h });
    if (!roleRes.ok) return undefined;
    const role = (await roleRes.text()).trim().split('\n')[0];
    if (!role) return undefined;

    const credRes = await doFetch(`${base}/latest/meta-data/iam/security-credentials/${role}`, {
      headers: h,
    });
    if (!credRes.ok) return undefined;
    return toResolved(await credRes.json());
  } catch {
    // Not on EC2, or the metadata service is blocked. Not an error at this layer -- the
    // caller reports "no credentials found" once every source has been tried.
    return undefined;
  }
}

function toResolved(body: unknown): Resolved | undefined {
  const b = body as {
    AccessKeyId?: string;
    SecretAccessKey?: string;
    Token?: string;
    Expiration?: string;
  };
  if (!b?.AccessKeyId || !b.SecretAccessKey) return undefined;
  return {
    creds: {
      accessKeyId: b.AccessKeyId,
      secretAccessKey: b.SecretAccessKey,
      sessionToken: b.Token,
    },
    expiresAt: b.Expiration ? Date.parse(b.Expiration) : Date.now() + 3600_000,
  };
}