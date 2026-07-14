import { randomBytes, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { IssuerKey } from '../credentials/keystore';
import { VpVerifier } from './vp-verifier';
import { Oid4vpStore, PresentationRequestRecord } from './ports';

/**
 * OpenID for Verifiable Presentations.
 *
 * This is the other half of interoperability. OpenID4VCI let a wallet *get* a residency
 * credential; this lets a wallet *present* one -- to a clinic, a subsidy desk, a bank --
 * without that relying party having to integrate anything OpenResidency-specific.
 *
 * The flow:
 *   1. A relying party creates a presentation request. It gets back an `openid4vp://`
 *      URI to render as a QR.
 *   2. The wallet scans it, fetches the signed Request Object, and shows the citizen what
 *      is being asked for and by whom.
 *   3. The citizen consents. The wallet posts a `vp_token` to our response endpoint.
 *   4. The relying party polls for the outcome.
 *
 * The security properties this buys over the old `POST /residency/verify` are set out in
 * vp-verifier.ts. In short: that endpoint could tell you a credential was genuine, but not
 * that the person in front of you held it, nor that it was presented to you rather than
 * replayed from somebody else's transaction.
 */

const REQUEST_TTL_SECONDS = 5 * 60;

export class Oid4vpError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = 'Oid4vpError';
  }
}

export interface Oid4vpConfig {
  /** Public origin of this deployment. */
  baseUrl: string;
  /**
   * The verifier's identifier, as it appears in `client_id` and in the presentation's
   * `aud`. A DID, so that a wallet can resolve our key and check the request signature
   * without a PKI or a network round-trip.
   */
  clientId: string;
  /** Shown to the citizen in the wallet's consent screen. */
  clientName: string;
}

export interface CreatedPresentationRequest {
  requestId: string;
  /** The deep link the relying party renders as a QR. */
  requestUri: string;
  expiresAt: string;
}

export class Oid4vpService {
  constructor(
    private cfg: Oid4vpConfig,
    private store: Oid4vpStore,
    private verifier: () => VpVerifier,
    private key: IssuerKey,
    /** The credential type we ask for. */
    private credentialType = 'StateResidencyCredential',
  ) {}

  // ---------------------------------------------------------------------------
  // 1. The relying party creates a request
  // ---------------------------------------------------------------------------

  async createRequest(opts: {
    purpose?: string;
    reference?: string;
  }): Promise<CreatedPresentationRequest> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + REQUEST_TTL_SECONDS * 1000);

    const record: PresentationRequestRecord = {
      id: randomUUID(),
      // The nonce is the freshness challenge. It is what the holder signs over, and it is
      // why a presentation captured from one transaction cannot be replayed into another.
      nonce: randomBytes(24).toString('base64url'),
      clientId: this.cfg.clientId,
      purpose: opts.purpose ?? 'Confirm state residency',
      reference: opts.reference,
      status: 'pending',
      expiresAt: expiresAt.toISOString(),
      createdAt: now.toISOString(),
    };
    await this.store.saveRequest(record);

    // Passed by reference: the wallet fetches the signed Request Object from request_uri.
    // Unlike the credential offer, there is no secret here to keep out of the QR -- and
    // by reference lets us SIGN the request, which is what allows the wallet to tell the
    // citizen who is really asking. An unsigned request is an unauthenticated request.
    const requestUri = `${this.cfg.baseUrl}/openid4vp/request/${record.id}`;
    const params = new URLSearchParams({
      client_id: this.cfg.clientId,
      request_uri: requestUri,
    });

    return {
      requestId: record.id,
      requestUri: `openid4vp://authorize?${params.toString()}`,
      expiresAt: record.expiresAt,
    };
  }

  // ---------------------------------------------------------------------------
  // 2. The wallet fetches the Request Object
  // ---------------------------------------------------------------------------

  /**
   * The Request Object, as a signed JWT.
   *
   * Signed so the wallet can verify who is asking before showing the citizen a consent
   * prompt. If this were unsigned, anything that could display a QR could impersonate a
   * hospital and harvest residency data.
   */
  async requestObject(requestId: string): Promise<string> {
    const record = await this.store.findRequest(requestId);
    if (!record) throw new Oid4vpError('invalid_request', 'unknown presentation request', 404);
    if (new Date(record.expiresAt).getTime() < Date.now()) {
      throw new Oid4vpError('invalid_request', 'presentation request has expired', 404);
    }

    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      client_id: record.clientId,
      response_type: 'vp_token',
      // direct_post: the wallet POSTs the vp_token straight to us, rather than
      // redirecting through a browser. That suits an in-person counter, where the
      // relying party's screen and the citizen's phone are different devices.
      response_mode: 'direct_post',
      response_uri: `${this.cfg.baseUrl}/openid4vp/response/${record.id}`,
      nonce: record.nonce,
      state: record.id,
      client_metadata: {
        client_name: this.cfg.clientName,
        purpose: record.purpose,
      },
      // DCQL is the query language of OpenID4VP 1.0.
      dcql_query: this.dcqlQuery(),
      // Presentation Exchange is what wallets mid-migration (including Inji) still
      // understand. Emitting both means we do not have to guess which the wallet speaks;
      // it reads the one it knows and ignores the other.
      presentation_definition: this.presentationDefinition(record.id),
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: `${this.cfg.clientId}#${this.key.kid}`,
        typ: 'oauth-authz-req+jwt',
      })
      .setIssuer(record.clientId)
      .setAudience('https://self-issued.me/v2') // the wallet, per SIOPv2
      .setIssuedAt(now)
      .setExpirationTime(Math.floor(new Date(record.expiresAt).getTime() / 1000))
      .sign(this.key.privateKey);
  }

  /** OpenID4VP 1.0 Digital Credentials Query Language. */
  private dcqlQuery(): Record<string, unknown> {
    return {
      credentials: [
        {
          id: 'residency',
          format: 'ldp_vc',
          meta: { type_values: [['VerifiableCredential', this.credentialType]] },
          claims: [
            { path: ['credentialSubject', 'residentId'] },
            { path: ['credentialSubject', 'subnationalUnit', 'name'] },
            { path: ['credentialSubject', 'subnationalUnit', 'code'] },
          ],
        },
      ],
    };
  }

  /** The legacy Presentation Exchange definition, for wallets not yet on DCQL. */
  private presentationDefinition(id: string): Record<string, unknown> {
    return {
      id,
      input_descriptors: [
        {
          id: 'residency',
          name: 'State Residency Credential',
          purpose: 'Confirm you are a resident of this state',
          constraints: {
            fields: [
              {
                path: ['$.type', '$.vc.type'],
                filter: { type: 'array', contains: { const: this.credentialType } },
              },
            ],
          },
        },
      ],
    };
  }

  // ---------------------------------------------------------------------------
  // 3. The wallet posts the presentation
  // ---------------------------------------------------------------------------

  async handleResponse(
    requestId: string,
    body: { vp_token?: unknown; state?: string },
  ): Promise<Record<string, unknown>> {
    const record = await this.store.findRequest(requestId);
    if (!record) throw new Oid4vpError('invalid_request', 'unknown presentation request', 404);

    if (new Date(record.expiresAt).getTime() < Date.now()) {
      await this.store.completeRequest(requestId, 'failed', { reason: 'REQUEST_EXPIRED' });
      throw new Oid4vpError('invalid_request', 'presentation request has expired');
    }
    // A request is answered once. A second vp_token for the same request -- a captured
    // one, replayed -- must not be able to overwrite the verdict.
    if (record.status !== 'pending') {
      throw new Oid4vpError('invalid_request', 'this presentation request was already answered');
    }

    // OpenID4VP allows vp_token to be a string or (in 1.0, with DCQL) an object keyed by
    // the query id. Accept both rather than forcing wallets into one shape.
    const raw = body.vp_token;
    const vpToken =
      typeof raw === 'string'
        ? raw
        : typeof (raw as Record<string, unknown>)?.residency === 'string'
          ? String((raw as Record<string, unknown>).residency)
          : Array.isArray(raw) && typeof raw[0] === 'string'
            ? String(raw[0])
            : undefined;

    if (!vpToken) {
      await this.store.completeRequest(requestId, 'failed', { reason: 'NO_VP_TOKEN' });
      throw new Oid4vpError('invalid_request', 'vp_token is required');
    }

    const outcome = await this.verifier().verify(vpToken, {
      expectedNonce: record.nonce,
      expectedAudience: record.clientId,
    });

    const stored: Record<string, unknown> = {
      valid: outcome.valid,
      reason: outcome.reason,
      holderDid: outcome.holderDid,
      issuerDid: outcome.issuerDid,
      checkedRevocation: outcome.checkedRevocation,
      // Only the claims the relying party actually asked for. A verifier confirming
      // residency has no need for the person's date of birth or their foundational ID
      // reference, so we do not hand them over just because the credential carries them.
      claims: outcome.valid ? this.minimizeClaims(outcome.subject) : undefined,
      verifiedAt: new Date().toISOString(),
    };

    const recorded = await this.store.completeRequest(
      requestId,
      outcome.valid ? 'fulfilled' : 'failed',
      stored,
    );
    if (!recorded) {
      throw new Oid4vpError('invalid_request', 'this presentation request was already answered');
    }

    // The wallet gets a bare acknowledgement. The verdict goes to the relying party, who
    // is the one who asked -- telling the wallet *why* a presentation was rejected would
    // hand an attacker a debugging oracle.
    return { status: 'accepted' };
  }

  /**
   * Release only what was asked for.
   *
   * The residency credential carries a foundational assurance block that includes
   * `subjectRef` -- the tokenized reference to the person's national ID. A clinic
   * verifying residency has no business receiving it, and it is exactly the field whose
   * leakage the whole tokenization design exists to prevent. So it never leaves here.
   */
  private minimizeClaims(subject?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!subject) return undefined;
    const unit = subject.subnationalUnit as Record<string, unknown> | undefined;
    const person = subject.person as Record<string, unknown> | undefined;
    return {
      residentId: subject.residentId,
      subnationalUnit: unit ? { code: unit.code, name: unit.name, level: unit.level } : undefined,
      fullName: person?.fullName,
      provisional: subject.provisional,
    };
  }

  // ---------------------------------------------------------------------------
  // 4. The relying party collects the result
  // ---------------------------------------------------------------------------

  async result(requestId: string): Promise<Record<string, unknown>> {
    const record = await this.store.findRequest(requestId);
    if (!record) throw new Oid4vpError('invalid_request', 'unknown presentation request', 404);
    return {
      requestId: record.id,
      status: record.status,
      reference: record.reference,
      purpose: record.purpose,
      expiresAt: record.expiresAt,
      ...(record.outcome ? { outcome: record.outcome } : {}),
    };
  }
}
