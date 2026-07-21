import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { jwtVerify } from 'jose';
import { CountryConfig } from '../config/country-config';
import { IssuerKey } from '../credentials/keystore';
import { signJwt } from '../credentials/signer';
import { RESIDENCY_LDP_CONTEXT } from '../credentials/ldp-issuer';
import { verifyHolderProof, HolderProofError } from './holder-proof';
import { CredentialFormat, MintedCredential, ResidencyService } from '../residency/residency-service';
import { ResidencyStore } from '../residency/ports';
import { CredentialOfferRecord, Oid4vciStore } from './ports';

/**
 * OpenID for Verifiable Credential Issuance.
 *
 * The flow this implements is the *pre-authorized code* grant, because it is the one
 * that matches how residency enrollment actually happens:
 *
 *   1. A citizen presents themselves at an enrollment desk. An operator verifies them
 *      against the foundational ID (NIN, Aadhaar, ...). This produces a ResidentRecord.
 *      That step is unchanged -- it is the existing `POST /residency/issue`.
 *   2. The desk shows a QR code (the Credential Offer) and reads out a short PIN.
 *   3. The citizen scans it with their own wallet. The wallet exchanges the code + PIN
 *      for an access token, proves possession of a key on the device, and receives a
 *      credential bound to that key.
 *
 * The important property is step 3: the credential is bound to the citizen's key, not
 * handed to whoever called our API. That is what makes it a credential rather than a
 * bearer token.
 *
 * ---------------------------------------------------------------------------
 * A note on why this class is full of "and also the old way"
 * ---------------------------------------------------------------------------
 * OpenID4VCI reached Final 1.0 in September 2025. The wallets we most want to serve --
 * MOSIP's Inji above all -- still implement Draft 13, and the two are wire-incompatible
 * on the credential endpoint (`proof` vs `proofs`, `credential` vs `credentials`,
 * c_nonce in the token response vs a dedicated Nonce Endpoint).
 *
 * Picking one means locking out real users. So we speak both, and answer each wallet in
 * the dialect it addressed us in. Every such accommodation below is marked. When Draft
 * 13 wallets have aged out, deleting them should be mechanical.
 */

export const PRE_AUTHORIZED_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const sha256 = (v: string): string => createHash('sha256').update(v).digest('hex');

/** Constant-time compare of two hex digests, to keep code checks free of timing leaks. */
function hashesEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export class Oid4vciError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = 'Oid4vciError';
  }
}

export interface Oid4vciConfig {
  /** The Credential Issuer Identifier: the public base URL of this deployment. */
  credentialIssuer: string;
}

export interface CreatedOffer {
  offerId: string;
  /** The deep link a wallet scans, rendered as a QR by the enrollment console. */
  offerUri: string;
  /** The Credential Offer object carried in that link, for debugging and tests. */
  offer: Record<string, unknown>;
  /** The PIN to read out to the citizen. Returned once and never stored in the clear. */
  txCode: string;
  expiresAt: string;
  credentialConfigurationIds: string[];
}

/** The parsed shape of a credential request, in either dialect. */
interface ParsedCredentialRequest {
  /** Which wire dialect the wallet spoke, so we answer in the same one. */
  dialect: 'draft13' | 'final';
  configurationId?: string;
  format?: string;
  proofJwts: string[];
}

export class Oid4vciService {
  constructor(
    private cfg: Oid4vciConfig,
    private configs: () => CountryConfig[],
    private getConfig: (countryCode: string) => CountryConfig | undefined,
    private residency: ResidencyService,
    private residents: ResidencyStore,
    private store: Oid4vciStore,
    private key: IssuerKey,
  ) {}

  // ---------------------------------------------------------------------------
  // Identifiers
  // ---------------------------------------------------------------------------

  /**
   * The wallet profile for a country, falling back to the deployment's default country.
   *
   * The fallback exists because two endpoints have no country in scope: the Nonce Endpoint
   * is unauthenticated and carries no context at all, and token lifetimes are decided
   * before we resolve which credential is being requested. A single-country deployment --
   * which is the overwhelmingly common case -- is unaffected either way.
   */
  private wallet(countryCode?: string) {
    const cfg = (countryCode ? this.getConfig(countryCode) : undefined) ?? this.configs()[0];
    return cfg.wallet;
  }

  /**
   * A credential configuration id is namespaced by country because a single deployment
   * can serve several jurisdictions, each with its own issuer DID and validity rules.
   */
  configurationId(cfg: CountryConfig, format: CredentialFormat): string {
    return `${cfg.countryCode}_${cfg.credential.type}_${format}`;
  }

  private parseConfigurationId(
    id: string,
  ): { cfg: CountryConfig; format: CredentialFormat } | undefined {
    for (const cfg of this.configs()) {
      for (const format of cfg.wallet.formats) {
        if (this.configurationId(cfg, format) === id) return { cfg, format };
      }
    }
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // Metadata
  // ---------------------------------------------------------------------------

  /** OAuth 2.0 Authorization Server Metadata (RFC 8414). */
  authorizationServerMetadata(): Record<string, unknown> {
    const base = this.cfg.credentialIssuer;
    return {
      issuer: base,
      token_endpoint: `${base}/openid4vci/token`,
      // We support only the pre-authorized code grant. There is no authorization-code
      // flow here because there is nothing to authorize interactively: the citizen was
      // already authenticated in person, against their foundational ID, at the desk.
      grant_types_supported: [PRE_AUTHORIZED_CODE_GRANT],
      response_types_supported: [],
      'pre-authorized_grant_anonymous_access_supported': true,
      token_endpoint_auth_methods_supported: ['none'],
    };
  }

  /** OpenID4VCI Credential Issuer Metadata. */
  credentialIssuerMetadata(): Record<string, unknown> {
    const base = this.cfg.credentialIssuer;
    const configurations: Record<string, unknown> = {};

    for (const cfg of this.configs()) {
      for (const format of cfg.wallet.formats) {
        configurations[this.configurationId(cfg, format)] = this.configurationMetadata(cfg, format);
      }
    }

    return {
      credential_issuer: base,
      authorization_servers: [base],
      credential_endpoint: `${base}/openid4vci/credential`,
      // Advertised for 1.0 wallets. Draft 13 wallets ignore it and read c_nonce out of
      // the token response instead, which we also still provide.
      nonce_endpoint: `${base}/openid4vci/nonce`,
      batch_credential_issuance: { batch_size: 5 },
      display: this.configs().map((c) => ({
        name: c.credential.issuerName,
        locale: 'en-US',
      })),
      credential_configurations_supported: configurations,
    };
  }

  private configurationMetadata(cfg: CountryConfig, format: CredentialFormat): Record<string, unknown> {
    const display = [
      {
        name: `${cfg.countryName} State Residency Credential`,
        locale: 'en-US',
        background_color: '#12408a',
        text_color: '#FFFFFF',
      },
    ];

    // Draft 13 spells the claims map one way and 1.0 spells it as an array of paths.
    // Emit both; wallets read the one they know and ignore the other.
    const draft13Claims = {
      credentialSubject: {
        residentId: { display: [{ name: 'Residency ID', locale: 'en-US' }] },
        subnationalUnit: { display: [{ name: 'State / Province', locale: 'en-US' }] },
        person: { display: [{ name: 'Person', locale: 'en-US' }] },
        provisional: { display: [{ name: 'Provisional', locale: 'en-US' }] },
      },
    };
    const finalClaims = [
      { path: ['credentialSubject', 'residentId'], display: [{ name: 'Residency ID', locale: 'en-US' }] },
      { path: ['credentialSubject', 'subnationalUnit', 'name'], display: [{ name: 'State / Province', locale: 'en-US' }] },
      { path: ['credentialSubject', 'person', 'fullName'], display: [{ name: 'Full Name', locale: 'en-US' }] },
      { path: ['credentialSubject', 'provisional'], display: [{ name: 'Provisional', locale: 'en-US' }] },
    ];

    return {
      format,
      scope: `${cfg.countryCode}_${cfg.credential.type}`,
      // did:key for Ed25519 wallets, did:jwk for everything else (including the RSA
      // keys Inji generates). See holderDidFromJwk.
      cryptographic_binding_methods_supported: ['did:key', 'did:jwk'],
      credential_signing_alg_values_supported: ['EdDSA'],
      ...(format === 'ldp_vc' ? { credential_signing_suites_supported: ['eddsa-rdfc-2022'] } : {}),
      credential_definition: {
        '@context': format === 'ldp_vc' ? RESIDENCY_LDP_CONTEXT : cfg.credential.context,
        type: ['VerifiableCredential', cfg.credential.type],
      },
      proof_types_supported: {
        jwt: {
          // Whatever this country's wallet profile accepts. RS256 is in the default set
          // only because Inji hardcodes it; a deployment can drop it.
          proof_signing_alg_values_supported: [...cfg.wallet.proofAlgs],
        },
      },
      // Draft 13 position.
      display,
      claims: draft13Claims,
      // 1.0 position.
      credential_metadata: { display, claims: finalClaims },
    };
  }

  // ---------------------------------------------------------------------------
  // Credential Offer
  // ---------------------------------------------------------------------------

  /**
   * Create a Credential Offer for a resident who has already been enrolled.
   *
   * Returns a `openid-credential-offer://` URI (rendered as a QR by the enrollment
   * console) plus a transaction code. The tx_code is the second factor: scanning the QR
   * alone is not enough, so a photographed or shoulder-surfed QR does not yield a
   * credential.
   */
  async createOffer(residentId: string): Promise<CreatedOffer> {
    const record = await this.residents.findByResidentId(residentId);
    if (!record) throw new Oid4vciError('invalid_request', `unknown residentId ${residentId}`, 404);

    const cfg = this.getConfig(record.countryCode);
    if (!cfg) {
      throw new Oid4vciError('invalid_request', `no config for country ${record.countryCode}`, 404);
    }

    const preAuthorizedCode = randomBytes(32).toString('base64url');
    // A PIN of the configured length, uniformly sampled. randomInt is rejection-sampled,
    // so there is no modulo bias toward low digits.
    const digits = cfg.wallet.offer.txCodeLength;
    const txCode = String(randomInt(0, 10 ** digits)).padStart(digits, '0');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + cfg.wallet.offer.ttlSeconds * 1000);

    const configurationIds = cfg.wallet.formats.map((f) => this.configurationId(cfg, f));

    const offer: CredentialOfferRecord = {
      id: randomUUID(),
      preAuthorizedCodeHash: sha256(preAuthorizedCode),
      txCodeHash: sha256(txCode),
      residentId: record.residentId,
      countryCode: cfg.countryCode,
      credentialConfigurationIds: configurationIds,
      expiresAt: expiresAt.toISOString(),
      failedAttempts: 0,
      createdAt: now.toISOString(),
    };
    await this.store.saveOffer(offer);

    /*
     * The offer is passed BY VALUE: the QR carries the whole Credential Offer object,
     * pre-authorized code included, rather than a URL pointing at one.
     *
     * The alternative -- `credential_offer_uri`, where the wallet fetches the offer from
     * us -- would force us to keep the pre-authorized code in the clear at rest, since we
     * would have to hand it back on dereference. By value, we store only sha256(code) and
     * a database leak yields nothing redeemable.
     *
     * What that trades away is that the secret now sits in a QR code on a screen, where
     * it can be photographed. Three things make that acceptable:
     *   - the tx_code is a second factor, and is NOT in the QR (it is read out verbally),
     *   - the code is single-use and dies after 15 minutes, and
     *   - wrong tx_code guesses are counted, so the 6-digit PIN cannot be walked through.
     * A photographed QR alone is therefore not enough to obtain anybody's credential.
     */
    const offerObject = this.buildOfferObject(cfg, offer, preAuthorizedCode);
    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify(offerObject),
    )}`;

    return {
      offerId: offer.id,
      offerUri,
      offer: offerObject,
      txCode,
      expiresAt: expiresAt.toISOString(),
      credentialConfigurationIds: configurationIds,
    };
  }

  private buildOfferObject(
    cfg: CountryConfig,
    offer: CredentialOfferRecord,
    preAuthorizedCode: string,
  ): Record<string, unknown> {
    return {
      credential_issuer: this.cfg.credentialIssuer,
      credential_configuration_ids: offer.credentialConfigurationIds,
      grants: {
        [PRE_AUTHORIZED_CODE_GRANT]: {
          'pre-authorized_code': preAuthorizedCode,
          tx_code: {
            length: cfg.wallet.offer.txCodeLength,
            input_mode: 'numeric',
            description: `Enter the ${cfg.wallet.offer.txCodeLength}-digit code shown at the enrollment desk`,
          },
        },
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Token
  // ---------------------------------------------------------------------------

  /** Exchange a pre-authorized code (+ tx_code) for an access token. */
  async token(params: {
    grantType?: string;
    preAuthorizedCode?: string;
    txCode?: string;
  }): Promise<Record<string, unknown>> {
    if (params.grantType !== PRE_AUTHORIZED_CODE_GRANT) {
      throw new Oid4vciError(
        'unsupported_grant_type',
        `only ${PRE_AUTHORIZED_CODE_GRANT} is supported`,
      );
    }
    if (!params.preAuthorizedCode) {
      throw new Oid4vciError('invalid_request', 'pre-authorized_code is required');
    }

    const offer = await this.store.findOfferByCodeHash(sha256(params.preAuthorizedCode));
    if (!offer) throw new Oid4vciError('invalid_grant', 'unknown pre-authorized code');

    if (new Date(offer.expiresAt).getTime() < Date.now()) {
      throw new Oid4vciError('invalid_grant', 'pre-authorized code has expired');
    }
    // Single use. Without this, a code recovered from a wallet's logs could be redeemed
    // again to mint a second credential bound to an attacker's key.
    if (offer.redeemedAt) {
      throw new Oid4vciError('invalid_grant', 'pre-authorized code has already been used');
    }
    if (offer.failedAttempts >= this.wallet(offer.countryCode).offer.maxTxCodeAttempts) {
      throw new Oid4vciError('invalid_grant', 'too many incorrect transaction codes; offer is locked');
    }

    if (offer.txCodeHash) {
      if (!params.txCode) {
        throw new Oid4vciError('invalid_request', 'tx_code is required for this offer');
      }
      if (!hashesEqual(sha256(params.txCode), offer.txCodeHash)) {
        // Count the failure before returning, so a 6-digit PIN cannot be walked through.
        offer.failedAttempts += 1;
        await this.store.updateOffer(offer);
        throw new Oid4vciError('invalid_grant', 'incorrect transaction code');
      }
    }

    offer.redeemedAt = new Date().toISOString();
    await this.store.updateOffer(offer);

    const wallet = this.wallet(offer.countryCode);
    const cNonce = await this.mintNonce(offer.countryCode);
    const accessToken = await this.mintAccessToken(offer, cNonce);

    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: wallet.accessTokenTtlSeconds,
      authorization_details: offer.credentialConfigurationIds.map((id) => ({
        type: 'openid_credential',
        credential_configuration_id: id,
      })),
      // Draft 13 wallets read c_nonce from here; 1.0 wallets ignore it and call the Nonce
      // Endpoint. Emitting it is harmless to a 1.0 wallet, and it is what makes Inji work.
      c_nonce: cNonce,
      c_nonce_expires_in: wallet.nonceTtlSeconds,
    };
  }

  /**
   * Mint the access token.
   *
   * It is a signed JWT rather than an opaque string for one specific reason: the Inji
   * wallet does not read `c_nonce` from the token *response*. It parses the access token
   * as a JWT and reads `c_nonce` and `client_id` from the claims inside it. That is not
   * in any version of the spec -- it is an eSignet implementation detail -- but a wallet
   * that reads `c_nonce` as the literal string "null" produces a proof we must reject,
   * and the citizen just sees "enrollment failed".
   *
   * So the claims are duplicated inside the token. Spec-compliant wallets never look.
   */
  private async mintAccessToken(offer: CredentialOfferRecord, cNonce: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const wallet = this.wallet(offer.countryCode);
    return signJwt(
      this.key.signer,
      { kid: this.key.kid, typ: 'at+jwt' },
      {
        offer_id: offer.id,
        resident_id: offer.residentId,
        country_code: offer.countryCode,
        credential_configuration_ids: offer.credentialConfigurationIds,
        // These two are in NO version of the spec. They exist because Inji reads c_nonce
        // and client_id from INSIDE the access token rather than from the token response.
        // A deployment that does not serve Inji should turn this off rather than emit
        // non-standard claims for nobody's benefit.
        ...(wallet.compatibility.cNonceInAccessToken
          ? { c_nonce: cNonce, client_id: this.cfg.credentialIssuer }
          : {}),
        iss: this.cfg.credentialIssuer,
        aud: this.cfg.credentialIssuer,
        sub: offer.residentId,
        jti: randomUUID(),
        iat: now,
        exp: now + wallet.accessTokenTtlSeconds,
      },
    );
  }

  private async verifyAccessToken(authorization?: string): Promise<{
    offerId: string;
    residentId: string;
    countryCode: string;
    configurationIds: string[];
  }> {
    const token = /^Bearer (.+)$/i.exec(authorization ?? '')?.[1];
    if (!token) {
      throw new Oid4vciError('invalid_token', 'a Bearer access token is required', 401);
    }
    try {
      const { payload } = await jwtVerify(token, this.key.publicKey, {
        issuer: this.cfg.credentialIssuer,
        audience: this.cfg.credentialIssuer,
      });
      return {
        offerId: String(payload.offer_id),
        residentId: String(payload.resident_id),
        countryCode: String(payload.country_code),
        configurationIds: (payload.credential_configuration_ids as string[]) ?? [],
      };
    } catch {
      throw new Oid4vciError('invalid_token', 'access token is invalid or expired', 401);
    }
  }

  // ---------------------------------------------------------------------------
  // Nonce
  // ---------------------------------------------------------------------------

  /** Mint and store a c_nonce. Stored hashed: a DB read must not yield a usable nonce. */
  private async mintNonce(countryCode?: string): Promise<string> {
    const nonce = randomBytes(24).toString('base64url');
    await this.store.saveNonce({
      nonceHash: sha256(nonce),
      expiresAt: new Date(
        Date.now() + this.wallet(countryCode).nonceTtlSeconds * 1000,
      ).toISOString(),
    });
    return nonce;
  }

  /** The Nonce Endpoint (OpenID4VCI 1.0). Unprotected by design, per spec. */
  async nonce(): Promise<Record<string, unknown>> {
    return { c_nonce: await this.mintNonce() };
  }

  // ---------------------------------------------------------------------------
  // Credential
  // ---------------------------------------------------------------------------

  /**
   * Work out which dialect the wallet is speaking, and what it asked for.
   *
   * Draft 13 sends `format` + `credential_definition` and a singular `proof`.
   * 1.0 sends `credential_configuration_id` and a plural `proofs`.
   * We accept either, and remember which so the response matches.
   */
  private parseCredentialRequest(
    body: Record<string, unknown>,
    wallet: { compatibility: { draft13: boolean } },
  ): ParsedCredentialRequest {
    const proofJwts: string[] = [];

    const proofs = body.proofs as { jwt?: unknown } | undefined;
    if (proofs?.jwt) {
      if (!Array.isArray(proofs.jwt)) {
        throw new Oid4vciError('invalid_proof', 'proofs.jwt must be an array');
      }
      proofJwts.push(...proofs.jwt.map(String));
    }

    const proof = body.proof as { proof_type?: unknown; jwt?: unknown } | undefined;
    if (proof?.jwt) {
      if (proof.proof_type !== 'jwt') {
        throw new Oid4vciError('invalid_proof', "proof.proof_type must be 'jwt'");
      }
      proofJwts.push(String(proof.jwt));
    }

    if (proofJwts.length === 0) {
      // Refusing to issue without a proof is the whole point: a credential with no
      // holder binding is a bearer token, which is what we are trying to stop minting.
      throw new Oid4vciError('invalid_proof', 'a key proof is required; this issuer does not issue unbound credentials');
    }

    const configurationId = body.credential_configuration_id
      ? String(body.credential_configuration_id)
      : undefined;
    const format = body.format ? String(body.format) : undefined;

    // A request is "final" if it used a 1.0-only field. Draft 13 otherwise.
    const dialect: 'draft13' | 'final' =
      body.proofs != null || (configurationId != null && format == null) ? 'final' : 'draft13';

    // A deployment whose wallets have all moved to 1.0 can turn Draft 13 off. That is a
    // real security improvement, not just tidiness: it narrows the request surface we
    // accept, and the Draft 13 path is the one carrying the non-standard accommodations.
    if (dialect === 'draft13' && !wallet.compatibility.draft13) {
      throw new Oid4vciError(
        'invalid_credential_request',
        'this issuer no longer accepts the OpenID4VCI Draft 13 request format; ' +
          'send credential_configuration_id with a `proofs` array (OpenID4VCI 1.0)',
      );
    }

    return { dialect, configurationId, format, proofJwts };
  }

  async credential(
    authorization: string | undefined,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const token = await this.verifyAccessToken(authorization);
    const wallet = this.wallet(token.countryCode);
    const request = this.parseCredentialRequest(body, wallet);

    // Resolve which credential configuration is being asked for, and check the token
    // actually authorizes it -- a token minted for one offer must not be usable to mint
    // some other country's credential.
    const configurationId =
      request.configurationId ??
      token.configurationIds.find((id) => this.parseConfigurationId(id)?.format === request.format);

    if (!configurationId) {
      throw new Oid4vciError(
        'unknown_credential_configuration',
        `no credential configuration matches format '${request.format ?? '(none)'}'`,
      );
    }
    if (!token.configurationIds.includes(configurationId)) {
      throw new Oid4vciError(
        'credential_request_denied',
        'this access token does not authorize that credential configuration',
      );
    }

    const resolved = this.parseConfigurationId(configurationId);
    if (!resolved) {
      throw new Oid4vciError('unknown_credential_configuration', `unknown id '${configurationId}'`);
    }

    // Verify every key proof. A batch shares one nonce, so consume it at most once --
    // otherwise the first proof would burn the nonce and the rest would fail.
    const nonceResults = new Map<string, boolean>();
    const consumeNonce = async (nonce: string): Promise<boolean> => {
      const cached = nonceResults.get(nonce);
      if (cached !== undefined) return cached;
      const ok = await this.store.consumeNonce(sha256(nonce));
      nonceResults.set(nonce, ok);
      return ok;
    };

    const holders: string[] = [];
    for (const jwt of request.proofJwts) {
      try {
        const result = await verifyHolderProof(jwt, {
          credentialIssuer: this.cfg.credentialIssuer,
          allowedAlgs: wallet.proofAlgs,
          consumeNonce,
        });
        holders.push(result.holderDid);
      } catch (e) {
        if (e instanceof HolderProofError) throw new Oid4vciError(e.code, e.message);
        throw e;
      }
    }

    const record = await this.residents.findByResidentId(token.residentId);
    if (!record) {
      throw new Oid4vciError('credential_request_denied', 'resident record no longer exists', 404);
    }

    const minted: MintedCredential[] = [];
    for (const holderDid of holders) {
      minted.push(await this.residency.mintForHolder(resolved.cfg, record, holderDid, resolved.format));
    }

    return this.formatCredentialResponse(minted, request, resolved.format, resolved.cfg.countryCode);
  }

  /** Answer in whichever dialect the wallet used. */
  private async formatCredentialResponse(
    minted: MintedCredential[],
    request: ParsedCredentialRequest,
    format: CredentialFormat,
    countryCode: string,
  ): Promise<Record<string, unknown>> {
    if (request.dialect === 'final') {
      return { credentials: minted.map((m) => ({ credential: m.credential })) };
    }

    // Draft 13: a singular `credential`, plus a fresh c_nonce for the next request.
    return {
      format,
      credential: minted[0].credential,
      c_nonce: await this.mintNonce(countryCode),
      c_nonce_expires_in: this.wallet(countryCode).nonceTtlSeconds,
    };
  }
}
