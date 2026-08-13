// SPDX-License-Identifier: Apache-2.0
import {
  createCipheriv,
  createHash,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID,
  createSign,
  constants as cryptoConstants,
  X509Certificate,
} from 'node:crypto';
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';
import { tokenizeSubject } from '../util';

/**
 * MOSIP ID Authentication (IDA) as a foundational provider.
 *
 * Every other provider here is a REST call described in YAML, because most national ID
 * APIs are exactly that. IDA is not: the request body is an encrypted envelope, and getting
 * any part of its construction wrong produces a request the server rejects with an error
 * that does not say which part. So this is a real adapter, and the envelope is the whole
 * reason it exists:
 *
 *   1. a fresh AES-256 session key encrypts the actual request block (AES/GCM);
 *   2. the session key is encrypted to MOSIP's partner certificate (RSA-OAEP, SHA-256);
 *   3. a SHA-256 digest of the request block, hex-encoded, is encrypted under the SAME
 *      session key and sent as `requestHMAC`;
 *   4. the SHA-256 thumbprint of that certificate is sent so MOSIP knows which key to use
 *      after a rotation;
 *   5. the whole body is signed as a detached JWS in a `signature` header, with the
 *      partner's signing certificate in `x5c`.
 *
 * Three details are not what a careful reader would guess, and each was taken from MOSIP's
 * own client code rather than from prose:
 *
 *   - The GCM IV is APPENDED AFTER the ciphertext, not prepended, and it is 16 bytes (the
 *     AES block size) rather than the usual 12.
 *   - The digest in `requestHMAC` is UPPERCASE hex.
 *   - Every base64 field is URL-safe and UNPADDED.
 *
 * WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT. IDA answers "did this person authenticate
 * against this identity" -- by OTP to the registered device, or by demographic match. That
 * is an authenticating provider in the sense the binding model means: a success is
 * `authoritative_authentication`, not a bare lookup, and `authenticatesApplicant` is
 * therefore set for it rather than being left to config.
 *
 * It does not retrieve attributes. IDA's `/auth` endpoint returns a yes or a no, and the
 * demographic attributes in a successful response are the ones the APPLICANT submitted and
 * MOSIP CONFIRMED -- which is a stronger statement than a lookup returning them, and the
 * only one this endpoint supports. Attribute retrieval is the separate eKYC endpoint, whose
 * response decryption needs a partner encryption key and a live deployment to test against;
 * it is deliberately not implemented here rather than implemented blind.
 */

export interface MosipIdaExtra {
  /** Env var holding the MISP licence key. Never the key itself. */
  mispLicenseKeyEnv: string;
  partnerId: string;
  /** Env var holding the policy-linked partner API key. */
  partnerApiKeyEnv: string;
  /**
   * MOSIP's partner certificate (PEM), to which the session key is encrypted. This is
   * public material -- it is the certificate MOSIP publishes to partners -- so unlike the
   * keys above it belongs in config rather than the environment.
   */
  idaCertificatePem: string;
  /** Env var holding the partner's signing key (PKCS#8 PEM) for the `signature` header. */
  signingKeyEnv: string;
  /** The partner's signing certificate (PEM), sent as `x5c` so MOSIP can check the JWS. */
  signingCertificatePem: string;
  /** `domainUri` and `env` as MOSIP issued them to this partner. */
  domainUri: string;
  environment: string;
  /** Which identifier the resident presents. */
  individualIdType?: 'UIN' | 'VID';
  /** Which identifier key in `input.identifiers` carries it. Defaults to `individualId`. */
  individualIdKey?: string;
  /** OTP delivery channels requested by initiateChallenge(). */
  otpChannels?: ('PHONE' | 'EMAIL')[];
  /** API version, as MOSIP versions it. */
  version?: string;
  /** Consent flag sent to MOSIP; the deployment is asserting it obtained consent. */
  consentObtained?: boolean;
}

/** Demographic fields IDA will match on, and the identifier keys they read from. */
const DEMOGRAPHIC_KEYS = ['name', 'dob', 'gender', 'phoneNumber', 'emailId'] as const;

const AUTH_ID = 'mosip.identity.auth';
const OTP_ID = 'mosip.identity.otp';

const b64url = (b: Buffer): string => b.toString('base64url');

/** MOSIP timestamps: `2022-12-01T03:22:46.720Z`. */
function utcTimestamp(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, '$1Z');
}

/**
 * AES-GCM exactly as MOSIP's kernel does it.
 *
 * The layout is the part worth stating: `ciphertext || tag || iv`. The IV goes LAST, which
 * is not what any conventional implementation does -- MOSIP's decrypt reads it from the
 * final block-size bytes -- and a client that prepends it produces a body that fails to
 * decrypt with no indication of why. The IV is 16 bytes because the Java implementation
 * sizes it from the cipher's block size rather than GCM's 12-byte recommendation.
 */
export function mosipSymmetricEncrypt(key: Buffer, plaintext: Buffer): Buffer {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([encrypted, cipher.getAuthTag(), iv]);
}

/** RSA-OAEP with SHA-256 and MGF1-SHA-256, which is what MOSIP's asymmetric encrypt uses. */
export function mosipAsymmetricEncrypt(certificatePem: string, plaintext: Buffer): Buffer {
  const publicKey = createPublicKey(certificatePem);
  return publicEncrypt(
    {
      key: publicKey,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    plaintext,
  );
}

/** SHA-256 over the certificate's DER encoding. */
export function certificateThumbprint(certificatePem: string): Buffer {
  const cert = new X509Certificate(certificatePem);
  return createHash('sha256').update(cert.raw).digest();
}

/** UPPERCASE hex SHA-256, which is what MOSIP's digestAsPlainText produces. */
export function mosipDigest(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
}

export class MosipIdaAdapter implements FoundationalProvider {
  readonly code = 'MOSIP_IDA';
  private cfg!: ProviderConfig;
  private extra!: MosipIdaExtra;
  private pepper: string;

  constructor(
    pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper',
    private fetchImpl: typeof fetch = fetch,
  ) {
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
    const extra = config.extra as unknown as MosipIdaExtra | undefined;
    // Checked at init, not at the first sign-in. A deployment missing its partner identity
    // should fail to start, not fail for the first resident who tries to use it.
    const missing = (
      [
        'mispLicenseKeyEnv',
        'partnerId',
        'partnerApiKeyEnv',
        'idaCertificatePem',
        'signingKeyEnv',
        'signingCertificatePem',
        'domainUri',
        'environment',
      ] as const
    ).filter((k) => !extra?.[k]);
    if (!extra || missing.length) {
      throw new Error(
        `MOSIP_IDA needs foundational.extra.{${missing.join(', ')}}: these come from partner ` +
          'onboarding and cannot be defaulted',
      );
    }
    if (!config.baseUrl) throw new Error('MOSIP_IDA needs a baseUrl');
    this.extra = extra;
  }

  /** `/idauthentication/v1/{kind}/{misp}/{partnerId}/{apiKey}` */
  private endpoint(kind: 'auth' | 'otp'): string {
    const misp = this.requireEnv(this.extra.mispLicenseKeyEnv);
    const apiKey = this.requireEnv(this.extra.partnerApiKeyEnv);
    const base = this.cfg.baseUrl!.replace(/\/$/, '');
    return `${base}/idauthentication/v1/${kind}/${encodeURIComponent(misp)}/${encodeURIComponent(
      this.extra.partnerId,
    )}/${encodeURIComponent(apiKey)}`;
  }

  private requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is not set in the environment`);
    return value;
  }

  private individualId(input: FoundationalVerificationInput): string {
    return (input.identifiers[this.extra.individualIdKey ?? 'individualId'] ?? '').trim();
  }

  /**
   * The detached JWS that MOSIP checks against the partner's registered signing certificate.
   *
   * Detached (`b64: false`, payload omitted) with the certificate chain in `x5c`, which is
   * what MOSIP's own client sends. The payload signed is the exact body bytes transmitted,
   * so the signature covers the encrypted envelope rather than a re-serialization of it --
   * re-serializing JSON to sign it is how signatures end up covering something subtly
   * different from what was sent.
   */
  private signBody(body: string): string {
    const pem = this.requireEnv(this.extra.signingKeyEnv);
    const x5c = new X509Certificate(this.extra.signingCertificatePem).raw.toString('base64');
    const encodedHeader = Buffer.from(
      JSON.stringify({ alg: 'RS256', b64: false, crit: ['b64'], x5c: [x5c] }),
    ).toString('base64url');

    // RFC 7797 signing input: `<encoded header>.<raw body bytes>`, with the payload then
    // omitted from the compact form.
    const signer = createSign('RSA-SHA256');
    signer.update(
      Buffer.concat([Buffer.from(`${encodedHeader}.`, 'utf8'), Buffer.from(body, 'utf8')]),
    );
    signer.end();
    return `${encodedHeader}..${signer.sign(pem).toString('base64url')}`;
  }

  private async post(url: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const body = JSON.stringify(payload);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 10000);
    try {
      const res = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          signature: this.signBody(body),
          authorization: 'Bearer',
        },
        body,
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`PROVIDER_HTTP_${res.status}`);
      return (await res.json()) as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Build the encrypted envelope shared by every IDA auth request. */
  private encryptRequest(requestBlock: Record<string, unknown>): Record<string, string> {
    const sessionKey = randomBytes(32);
    const json = Buffer.from(JSON.stringify(requestBlock), 'utf8');
    return {
      request: b64url(mosipSymmetricEncrypt(sessionKey, json)),
      // The digest is taken over the PLAINTEXT block and then encrypted under the same
      // session key. It is not a MAC over the ciphertext, despite the field's name.
      requestHMAC: b64url(
        mosipSymmetricEncrypt(sessionKey, Buffer.from(mosipDigest(json), 'utf8')),
      ),
      requestSessionKey: b64url(mosipAsymmetricEncrypt(this.extra.idaCertificatePem, sessionKey)),
      thumbprint: b64url(certificateThumbprint(this.extra.idaCertificatePem)),
    };
  }

  /**
   * Request an OTP to the device MOSIP has registered against the identity.
   *
   * This is what makes IDA an authenticating provider rather than a lookup: the code goes
   * to the contact on the AUTHORITATIVE record, so returning it proves the applicant holds
   * that device -- not merely that they know the identity number.
   */
  async initiateChallenge(input: FoundationalVerificationInput) {
    const individualId = this.individualId(input);
    if (!individualId) throw new Error('MISSING_INDIVIDUAL_ID');

    const transactionID = this.newTransactionId();
    const payload = {
      id: OTP_ID,
      version: this.extra.version ?? '1.0',
      individualId,
      individualIdType: this.extra.individualIdType ?? 'UIN',
      otpChannel: this.extra.otpChannels ?? ['PHONE'],
      transactionID,
      requestTime: utcTimestamp(),
      metadata: {},
    };

    const body = await this.post(this.endpoint('otp'), payload);
    const errors = (body.errors as { errorCode?: string }[] | undefined) ?? [];
    if (errors.length) throw new Error(`IDA_${errors[0]?.errorCode ?? 'OTP_FAILED'}`);

    return {
      type: 'otp' as const,
      channel: (this.extra.otpChannels ?? ['PHONE'])[0].toLowerCase(),
      // MOSIP correlates the OTP with the auth call by transactionID, so that -- not an
      // identifier of our own -- is what has to come back to verify().
      challengeRef: transactionID,
    };
  }

  async verify(input: FoundationalVerificationInput): Promise<FoundationalVerificationResult> {
    const individualId = this.individualId(input);
    if (!individualId) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: 'MISSING_INDIVIDUAL_ID',
      };
    }

    const otp = input.identifiers.otp;
    const demographics = this.demographicsFrom(input);
    if (!otp && !Object.keys(demographics).length) {
      // Nothing to authenticate with. Ask for an OTP rather than sending IDA a request that
      // asserts nothing and is refused.
      try {
        const challenge = await this.initiateChallenge(input);
        return {
          verified: false,
          providerCode: this.code,
          assuranceLevel: 'none',
          pendingChallenge: challenge,
          reason: 'OTP_REQUIRED',
        };
      } catch (e) {
        return {
          verified: false,
          providerCode: this.code,
          assuranceLevel: 'none',
          reason: (e as Error).message,
        };
      }
    }

    const transactionID = input.challengeRef ?? this.newTransactionId();
    const requestBlock: Record<string, unknown> = { timestamp: utcTimestamp() };
    if (otp) requestBlock.otp = otp;
    if (Object.keys(demographics).length) requestBlock.demographics = demographics;

    const payload = {
      id: AUTH_ID,
      version: this.extra.version ?? '1.0',
      individualId,
      individualIdType: this.extra.individualIdType ?? 'UIN',
      transactionID,
      requestTime: utcTimestamp(),
      specVersion: this.extra.version ?? '1.0',
      thumbprint: '',
      domainUri: this.extra.domainUri,
      env: this.extra.environment,
      consentObtained: this.extra.consentObtained ?? true,
      requestedAuth: {
        otp: !!otp,
        demo: Object.keys(demographics).length > 0,
        bio: false,
      },
      ...this.encryptRequest(requestBlock),
    };

    let body: Record<string, unknown>;
    try {
      body = await this.post(this.endpoint('auth'), payload);
    } catch (e) {
      const message = (e as Error).message;
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: message.startsWith('PROVIDER_HTTP_') ? message : 'PROVIDER_UNREACHABLE',
      };
    }

    const response = (body.response ?? {}) as { authStatus?: boolean };
    const errors = (body.errors as { errorCode?: string }[] | undefined) ?? [];
    if (!response.authStatus) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        // MOSIP's error code is the only actionable thing in a failure, and it distinguishes
        // a wrong OTP from an expired one from a blocked identity.
        reason: errors.length ? `IDA_${errors[0]?.errorCode ?? 'AUTH_FAILED'}` : 'AUTH_FAILED',
      };
    }

    return {
      verified: true,
      providerCode: this.code,
      assuranceLevel: this.cfg.assuranceOnSuccess,
      identity: {
        subjectRef: tokenizeSubject(this.code, individualId, this.pepper),
        // The demographics MOSIP just CONFIRMED, not attributes it returned: /auth answers
        // yes or no, and claiming more than that would overstate what was established.
        fullName: demographics.name,
        dateOfBirth: demographics.dob,
        gender: demographics.gender,
        phone: demographics.phoneNumber,
        email: demographics.emailId,
      },
      applicantBinding: {
        // An OTP to the registered device, or a demographic match performed by the
        // authority itself. Either way the source vouched, which is what this method means.
        method: 'authoritative_authentication',
        ref: transactionID,
        verifiedAt: new Date().toISOString(),
      },
    };
  }

  private demographicsFrom(input: FoundationalVerificationInput): Record<string, string> {
    const out: Record<string, string> = {};
    for (const key of DEMOGRAPHIC_KEYS) {
      const value = input.identifiers[key];
      if (value) out[key] = value;
    }
    return out;
  }

  /** MOSIP requires a transaction id per exchange; it correlates OTP with auth. */
  private newTransactionId(): string {
    return randomUUID().replace(/-/g, '').slice(0, 10);
  }
}