// SPDX-License-Identifier: Apache-2.0
/**
 * OpenResidency Interoperability SDK.
 *
 * A small, dependency-free typed client for the OpenResidency API. Uses the global
 * fetch (Node 18+ or any browser).
 *
 * Two layers:
 *
 * - `client.request(method, path, opts)` reaches EVERY operation in docs/openapi.yaml. The
 *   path, its parameters, the request body and the response are typed from `openapi.ts`,
 *   which is generated from that file (`npm run sdk:generate` at the repository root) and
 *   checked in CI against the controllers, so the client cannot fall behind the server.
 * - Named methods (`issueResidency`, `transitionRelationship`, ...) wrap the operations a
 *   sector service, a wallet backend or a registry console calls, and choose the right
 *   credentials for each. They are thin: each is one `request` call.
 *
 * Browser-driven flows (the OIDC login interaction under /interaction, WebAuthn
 * registration, the upstream enrolment callback) have no named method; a server-side
 * client does not drive them, but `request` reaches them if one has to.
 */
import type { components, paths } from './openapi.js';

export type { components, paths } from './openapi.js';

// ---------------------------------------------------------------------------------------
// Typing the generated contract
// ---------------------------------------------------------------------------------------

export type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete';

type OperationLike = { responses: unknown };

/** The paths that serve `M` (`PathsFor<'post'>` is every POST route). */
export type PathsFor<M extends HttpMethod> = {
  [P in keyof paths]: paths[P][M] extends OperationLike ? P : never;
}[keyof paths];

/** The operation object for `M path`. */
export type Operation<M extends HttpMethod, P extends PathsFor<M>> = paths[P][M] extends OperationLike
  ? paths[P][M]
  : never;

export type PathParams<O> = O extends { parameters: { path: infer X } } ? X : never;
export type QueryParams<O> = O extends { parameters: { query?: infer Q } }
  ? Exclude<Q, undefined>
  : never;
export type RequestBody<O> = O extends { requestBody: { content: { 'application/json': infer B } } }
  ? B
  : O extends { requestBody?: { content: { 'application/json': infer B } } }
    ? B | undefined
    : never;

type SuccessCode = 200 | 201 | 202 | 204;
type ContentOf<R> = R extends { content: infer C }
  ? C[keyof C]
  : R extends { content?: never }
    ? undefined
    : unknown;
/** The body of a successful response, whatever its media type. `undefined` for 204. */
export type ResponseBody<O> = O extends { responses: infer R }
  ? { [K in keyof R & SuccessCode]: ContentOf<R[K]> }[keyof R & SuccessCode]
  : never;

/**
 * Which credential a call carries.
 *
 * - `'auto'` (default): the operator credential from `ClientOptions` if one is set,
 *   otherwise nothing. Right for the named methods, wrong for nothing.
 * - `'operator'`: an operator credential is required; throws before the request if none
 *   is configured, so a misconfigured service fails at the call site and not with a 401.
 * - `'none'`: send no credential even if one is configured (a public endpoint).
 * - `{ bearer }`: a bearer token for this call only, such as the OpenID4VCI access token
 *   at `/openid4vci/credential`.
 * - `{ headers }`: arbitrary headers for this call only, such as `x-ussd-secret`.
 */
export type Auth = 'auto' | 'operator' | 'none' | { bearer: string } | { headers: Record<string, string> };

type PathOpt<O> = [PathParams<O>] extends [never] ? { path?: undefined } : { path: PathParams<O> };
type QueryOpt<O> = [QueryParams<O>] extends [never]
  ? { query?: undefined }
  : { query?: QueryParams<O> };
type BodyOpt<O> = [RequestBody<O>] extends [never]
  ? { body?: undefined }
  : undefined extends RequestBody<O>
    ? { body?: RequestBody<O> }
    : { body: RequestBody<O> };

/** Options for `request`, derived from the operation: what it needs is required. */
export type RequestOptions<O> = PathOpt<O> &
  QueryOpt<O> &
  BodyOpt<O> & {
    auth?: Auth;
    /** Extra headers, merged after the ones the client sets. */
    headers?: Record<string, string>;
    /** Override the `accept` header (default `application/json`). */
    accept?: string;
  };

type RequestArgs<O> = {} extends RequestOptions<O> ? [opts?: RequestOptions<O>] : [opts: RequestOptions<O>];

type Schema<K extends keyof components['schemas']> = components['schemas'][K];

// ---------------------------------------------------------------------------------------
// Client options and the stable, hand-written types the 0.1.0 methods return
// ---------------------------------------------------------------------------------------

export type AssuranceLevel = 'none' | 'basic' | 'verified' | 'high';

export interface ClientOptions {
  baseUrl: string;
  /**
   * Per-operator API key (`ork_...`), minted at POST /operator/keys.
   *
   * This is the credential to use: it identifies WHICH operator is calling, so privileged
   * actions are attributable in the audit log, it carries only the roles that operator
   * holds, and it can be rotated with an overlap window rather than a hard cutover.
   */
  operatorKey?: string;
  /**
   * Legacy shared admin key. Works only where the deployment still runs
   * `operatorAuth.mode: sharedKey`, and carries no identity or roles. Prefer operatorKey.
   *
   * @deprecated Use `operatorKey`.
   */
  adminKey?: string;
  /**
   * Bearer token from an operator SSO sign-in (`operatorAuth.mode: oidc` or `local`).
   * Send this when the caller is a person in a console rather than a machine.
   */
  operatorToken?: string;
  /** Optional custom fetch (for tests or non-standard runtimes). */
  fetch?: typeof fetch;
}

export interface IdentityVerifyRequest {
  countryCode: string;
  identifiers: Record<string, string>;
  challengeRef?: string;
  purpose?: string;
}

export interface IdentityVerifyResponse {
  verified: boolean;
  assuranceLevel?: AssuranceLevel;
  subjectRef?: string;
  attributes?: Record<string, unknown>;
  pendingChallenge?: boolean;
  challengeRef?: string;
  channel?: string;
  reason?: string;
}

export interface IssueRequest {
  countryCode: string;
  subnationalUnit: string;
  identifiers: Record<string, string>;
  holderId?: string;
  challengeRef?: string;
  proofOfResidence?: string;
  /**
   * Applicant phone in E.164, for one-time-code delivery. What is retained depends on the
   * deployment's `contactDirectory.mode`; it never reaches the credential or the audit log.
   */
  phone?: string;
  offline?: boolean;
}

export interface IssueResult {
  status: 'issued' | 'exists' | 'challenge' | 'rejected';
  residentId?: string;
  credentialJwt?: string;
  reason?: string;
  challenge?: { type: string; channel: string; challengeRef: string };
}

export interface ResidencyStatus {
  residentId: string;
  countryCode: string;
  subnationalUnit: string;
  assuranceLevel: string;
  provisional: boolean;
  createdAt: string;
}

export interface CredentialVerifyOutcome {
  valid: boolean;
  reason?: string;
  checkedRevocation?: boolean;
  subject?: Record<string, unknown>;
}

export interface ConsentRecord {
  id: string;
  residentId: string;
  relyingParty: string;
  purpose: string;
  scopes: string[];
  status: 'active' | 'revoked' | 'expired';
  grantedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  receiptId: string;
}

export interface AuditEvent {
  seq: number;
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  target?: string;
  countryCode?: string;
  outcome: 'success' | 'failure';
  metadata?: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export class OpenResidencyError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`OpenResidency API error ${status}`);
  }
}

// ---------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------

export class OpenResidencyClient {
  private baseUrl: string;
  private operatorKey?: string;
  private adminKey?: string;
  private operatorToken?: string;
  private doFetch: typeof fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.operatorKey = opts.operatorKey;
    this.adminKey = opts.adminKey;
    this.operatorToken = opts.operatorToken;
    this.doFetch = opts.fetch ?? fetch;
  }

  // ---- the whole contract ----

  /**
   * Call any operation in docs/openapi.yaml. Path parameters, query, body and the
   * response are typed from the generated contract:
   *
   * ```ts
   * const rel = await client.request('get', '/residency/{residentId}/relationship', {
   *   path: { residentId },
   * });
   * ```
   */
  request<M extends HttpMethod, P extends PathsFor<M>>(
    method: M,
    path: P,
    ...args: RequestArgs<Operation<M, P>>
  ): Promise<ResponseBody<Operation<M, P>>> {
    const opts = (args[0] ?? {}) as {
      path?: Record<string, string | number>;
      query?: Record<string, unknown>;
      body?: unknown;
      auth?: Auth;
      headers?: Record<string, string>;
      accept?: string;
    };
    return this.send(method, path, opts) as Promise<ResponseBody<Operation<M, P>>>;
  }

  // ---- health ----
  live() {
    return this.request('get', '/health/live', { auth: 'none' });
  }
  ready() {
    return this.request('get', '/health/ready', { auth: 'none' });
  }

  // ---- identity ----
  /** Operator action: needs the `registrar` role. */
  identityChallenge(countryCode: string, identifiers: Record<string, string>) {
    return this.send('post', '/identity/challenge', {
      body: { countryCode, identifiers },
      auth: 'operator',
    }) as Promise<{ challengeRequired: boolean; challengeRef?: string; channel?: string }>;
  }
  /** Operator action: needs the `registrar` role. */
  verifyIdentity(req: IdentityVerifyRequest) {
    return this.send('post', '/identity/verify', { body: req, auth: 'operator' }) as Promise<IdentityVerifyResponse>;
  }

  // ---- residency ----
  countries() {
    return this.send('get', '/residency/countries', { auth: 'none' }) as Promise<
      Array<{ countryCode: string; countryName: string; provider: string; inputs: unknown[] }>
    >;
  }
  /** Operator action: needs the `registrar` role. */
  issueResidency(req: IssueRequest) {
    return this.send('post', '/residency/issue', { body: req, auth: 'operator' }) as Promise<IssueResult>;
  }
  residencyStatus(residentId: string) {
    return this.send('get', '/residency/{residentId}', { path: { residentId } }) as Promise<ResidencyStatus>;
  }
  verifyCredential(credential: string, offline = false) {
    return this.send('post', '/residency/verify', {
      body: { credential, offline },
    }) as Promise<CredentialVerifyOutcome>;
  }
  /** Operator action: needs the `revoker` role. */
  revokeResidency(residentId: string) {
    return this.send('post', '/residency/revoke/{residentId}', {
      path: { residentId },
      body: {},
      auth: 'operator',
    }) as Promise<{ revoked: boolean }>;
  }
  /** Operator action: needs the `admin` role. Revokes first, then destroys personal data. */
  eraseResidency(residentId: string, body?: RequestBody<Operation<'post', '/residency/{residentId}/erase'>>) {
    return this.request('post', '/residency/{residentId}/erase', {
      path: { residentId },
      body,
      auth: 'operator',
    });
  }
  /** Operator action. Erases records whose retention period has ended. */
  retentionSweep(body?: RequestBody<Operation<'post', '/residency/retention/sweep'>>) {
    return this.request('post', '/residency/retention/sweep', { body, auth: 'operator' });
  }
  /** Operator action. Expires provisional registrations that were never completed. */
  provisionalSweep(body?: RequestBody<Operation<'post', '/residency/provisional/sweep'>>) {
    return this.request('post', '/residency/provisional/sweep', { body, auth: 'operator' });
  }
  /** Operator action. Re-verifies a resident against the foundational source. */
  reconcile(residentId: string, body: RequestBody<Operation<'post', '/residency/{residentId}/reconcile'>>) {
    return this.request('post', '/residency/{residentId}/reconcile', {
      path: { residentId },
      body,
      auth: 'operator',
    });
  }

  // ---- relationship and credential lifecycle (ORCS §6, §10) ----
  /** The relationship's ORCS state and how it got there. */
  relationship(residentId: string) {
    return this.request('get', '/residency/{residentId}/relationship', { path: { residentId } });
  }
  /** Operator action. Move the relationship to a new ORCS state. */
  transitionRelationship(
    residentId: string,
    body: RequestBody<Operation<'post', '/residency/{residentId}/relationship/transition'>>,
  ) {
    return this.request('post', '/residency/{residentId}/relationship/transition', {
      path: { residentId },
      body,
      auth: 'operator',
    });
  }
  /** The credential's ORCS status. */
  credential(residentId: string) {
    return this.request('get', '/residency/{residentId}/credential', { path: { residentId } });
  }
  /** Operator action. Move the credential to a new ORCS status. */
  transitionCredential(
    residentId: string,
    body: RequestBody<Operation<'post', '/residency/{residentId}/credential/transition'>>,
  ) {
    return this.request('post', '/residency/{residentId}/credential/transition', {
      path: { residentId },
      body,
      auth: 'operator',
    });
  }
  /** Why an application was refused, and how to appeal. */
  refusal(reference: string) {
    return this.request('get', '/residency/refusals/{reference}', { path: { reference } });
  }
  /** Operator action. Record the outcome of reviewing a refusal. */
  reviewRefusal(reference: string, body: RequestBody<Operation<'post', '/residency/refusals/{reference}/review'>>) {
    return this.request('post', '/residency/refusals/{reference}/review', {
      path: { reference },
      body,
      auth: 'operator',
    });
  }

  // ---- identity links (ORCS §11) ----
  /** A person's identity links, current and closed, their history, and whether a dispute restricts them. */
  identityLinks(residentId: string) {
    return this.request('get', '/residency/{residentId}/identity-links', { path: { residentId }, auth: 'operator' });
  }
  /** LINK an identifier to a person. The raw identifier is tokenized by the server and never stored. */
  linkIdentity(residentId: string, body: RequestBody<Operation<'post', '/residency/{residentId}/identity-links'>>) {
    return this.request('post', '/residency/{residentId}/identity-links', { path: { residentId }, body, auth: 'operator' });
  }
  /** One link and everything that ever happened to it. */
  identityLink(linkId: string) {
    return this.request('get', '/residency/identity-links/{linkId}', { path: { linkId }, auth: 'operator' });
  }
  /** DISPUTE a link. Issuance and wallet delivery are refused for the person until it is resolved. */
  disputeIdentityLink(linkId: string, reason: string) {
    return this.request('post', '/residency/identity-links/{linkId}/dispute', { path: { linkId }, body: { reason }, auth: 'operator' });
  }
  /** Resolve a dispute in the link's favour. */
  resolveIdentityLinkDispute(linkId: string, resolution: string) {
    return this.request('post', '/residency/identity-links/{linkId}/dispute/resolve', { path: { linkId }, body: { resolution }, auth: 'operator' });
  }
  /** UNLINK, keeping the history. The foundational identifier suspends the relationship first. Needs `revoker`. */
  unlinkIdentity(residentId: string, linkId: string, reason: string) {
    return this.request('post', '/residency/{residentId}/identity-links/{linkId}/unlink', { path: { residentId, linkId }, body: { reason }, auth: 'operator' });
  }
  /** RELINK the identifier to the right person after adjudication. Needs `revoker`. */
  relinkIdentity(linkId: string, body: RequestBody<Operation<'post', '/residency/identity-links/{linkId}/relink'>>) {
    return this.request('post', '/residency/identity-links/{linkId}/relink', { path: { linkId }, body, auth: 'operator' });
  }
  /** MERGE a duplicate into this resident. Needs `admin`. */
  mergeResidents(survivorId: string, body: RequestBody<Operation<'post', '/residency/{residentId}/merge'>>) {
    return this.request('post', '/residency/{residentId}/merge', { path: { residentId: survivorId }, body, auth: 'operator' });
  }
  /** A merge, and whether it has been split. */
  merge(mergeId: string) {
    return this.request('get', '/residency/merges/{mergeId}', { path: { mergeId }, auth: 'operator' });
  }
  /** SPLIT a merge, restoring the identifiers to the duplicate. Needs `admin`. */
  splitMerge(mergeId: string, reason: string) {
    return this.request('post', '/residency/merges/{mergeId}/split', { path: { mergeId }, body: { reason }, auth: 'operator' });
  }

  // ---- assurance (ORCS §7) ----
  assuranceProfiles() {
    return this.request('get', '/assurance/profiles', { auth: 'none' });
  }
  assuranceMappings() {
    return this.request('get', '/assurance/mappings', { auth: 'none' });
  }
  /** Resolve a source-specific assurance value to the ORCS assurance profile. */
  resolveAssurance(value: string) {
    return this.request('get', '/assurance/resolve/{value}', { path: { value }, auth: 'none' });
  }
  residentAssurance(residentId: string) {
    return this.request('get', '/residency/{residentId}/assurance', { path: { residentId } });
  }

  // ---- consent (ORCS §9) ----
  // The consent routes are operator-guarded server-side (support role), so they carry
  // credentials like the admin ones. They previously did not, and 401'd.
  listConsents(residentId: string) {
    return this.send('get', '/consent/resident/{residentId}', {
      path: { residentId },
      auth: 'operator',
    }) as Promise<{ residentId: string; consents: ConsentRecord[] }>;
  }
  grantConsent(req: {
    residentId: string;
    relyingParty: string;
    purpose: string;
    scopes: string[];
    relyingPartyName?: string;
    validityDays?: number;
  }) {
    return this.send('post', '/consent/grant', { body: req, auth: 'operator' }) as Promise<{
      consent: ConsentRecord;
      receipt: string;
    }>;
  }
  revokeConsent(id: string) {
    return this.send('post', '/consent/{id}/revoke', { path: { id }, body: {}, auth: 'operator' }) as Promise<{
      consent: ConsentRecord;
    }>;
  }
  legalBases() {
    return this.request('get', '/consent/legal-bases');
  }
  legalBasis(id: string) {
    return this.request('get', '/consent/legal-bases/{id}', { path: { id } });
  }
  /** Operator action. Withdraw a legal basis; consents resting on it stop being valid. */
  deactivateLegalBasis(id: string, body: RequestBody<Operation<'post', '/consent/legal-bases/{id}/deactivate'>>) {
    return this.request('post', '/consent/legal-bases/{id}/deactivate', { path: { id }, body, auth: 'operator' });
  }

  // ---- operator identity ----
  /** Local sign-in (`operatorAuth.mode: local`). The token goes in `ClientOptions.operatorToken`. */
  operatorLogin(body: RequestBody<Operation<'post', '/operator/login'>>) {
    return this.request('post', '/operator/login', { body, auth: 'none' });
  }
  /** The calling operator's identity and roles. */
  me() {
    return this.request('get', '/operator/me', { auth: 'operator' });
  }
  listOperators() {
    return this.request('get', '/operator/operators', { auth: 'operator' });
  }
  createOperator(body: RequestBody<Operation<'post', '/operator/operators'>>) {
    return this.request('post', '/operator/operators', { body, auth: 'operator' });
  }
  /** Disable (or with `disabled: false`, re-enable) an operator account. Needs the `admin` role. */
  disableOperator(operatorId: string, disabled = true) {
    return this.request('post', '/operator/operators/{id}/disable', {
      path: { id: operatorId },
      body: { disabled },
      auth: 'operator',
    });
  }
  listKeys() {
    return this.request('get', '/operator/keys', { auth: 'operator' });
  }
  /** Mint a per-operator API key. The secret is returned once. */
  createKey(body: RequestBody<Operation<'post', '/operator/keys'>>) {
    return this.request('post', '/operator/keys', { body, auth: 'operator' });
  }
  /** Mint a replacement key; the old one keeps working for the overlap window. */
  rotateKey(body: RequestBody<Operation<'post', '/operator/keys/rotate'>>) {
    return this.request('post', '/operator/keys/rotate', { body, auth: 'operator' });
  }
  revokeKey(body: RequestBody<Operation<'post', '/operator/keys/revoke'>>) {
    return this.request('post', '/operator/keys/revoke', { body, auth: 'operator' });
  }

  // ---- audit and admin (operator-authenticated) ----
  listResidents(params: { countryCode?: string; limit?: number; offset?: number } = {}) {
    return this.send('get', '/admin/residents', { query: params, auth: 'operator' }) as Promise<{
      total: number;
      residents: ResidencyStatus[];
    }>;
  }
  auditLog(params: { limit?: number; offset?: number; target?: string } = {}) {
    return this.send('get', '/audit', { query: params, auth: 'operator' }) as Promise<{
      count: number;
      events: AuditEvent[];
    }>;
  }
  verifyAuditChain() {
    return this.send('get', '/audit/verify', { auth: 'operator' }) as Promise<{
      ok: boolean;
      length: number;
      brokenAtSeq?: number;
    }>;
  }
  /** Counts by country. */
  stats() {
    return this.request('get', '/admin/stats', { auth: 'operator' });
  }
  /** Aggregate, non-PII statistics (the open-data surface), as JSON. */
  statistics(query?: QueryParams<Operation<'get', '/admin/statistics'>>) {
    return this.request('get', '/admin/statistics', { query, auth: 'operator' });
  }
  /** The same report as RFC 4180 CSV. */
  statisticsCsv(query?: QueryParams<Operation<'get', '/admin/statistics.csv'>>) {
    return this.request('get', '/admin/statistics.csv', { query, auth: 'operator', accept: 'text/csv' });
  }

  // ---- offline ----
  /** Render a credential as an SVG QR for paper or low-connectivity carriage. */
  qr(body: RequestBody<Operation<'post', '/offline/qr'>>) {
    return this.request('post', '/offline/qr', { body });
  }
  /** The USSD aggregator webhook. `secret` is the shared USSD_GATEWAY_SECRET. */
  ussd(body: RequestBody<Operation<'post', '/offline/ussd'>>, secret: string) {
    return this.request('post', '/offline/ussd', { body, auth: { headers: { 'x-ussd-secret': secret } } });
  }

  // ---- OpenID4VCI: issuing into a wallet ----
  credentialIssuerMetadata() {
    return this.request('get', '/.well-known/openid-credential-issuer', { auth: 'none' });
  }
  oauthAuthorizationServerMetadata() {
    return this.request('get', '/.well-known/oauth-authorization-server', { auth: 'none' });
  }
  /** Operator action. Create a credential offer for a resident's wallet to redeem. */
  createCredentialOffer(body: RequestBody<Operation<'post', '/openid4vci/offer'>>) {
    return this.request('post', '/openid4vci/offer', { body, auth: 'operator' });
  }
  /** The wallet side: exchange the pre-authorized code for an access token. */
  walletToken(body: RequestBody<Operation<'post', '/openid4vci/token'>>) {
    return this.request('post', '/openid4vci/token', { body, auth: 'none' });
  }
  walletNonce() {
    return this.request('post', '/openid4vci/nonce', { auth: 'none' });
  }
  /** The wallet side: obtain the credential with the access token from `walletToken`. */
  walletCredential(accessToken: string, body: RequestBody<Operation<'post', '/openid4vci/credential'>>) {
    return this.request('post', '/openid4vci/credential', { body, auth: { bearer: accessToken } });
  }

  // ---- OpenID4VP: asking a wallet to present ----
  /** Create a presentation request for a wallet to answer. */
  createPresentationRequest(body?: RequestBody<Operation<'post', '/openid4vp/request'>>) {
    return this.request('post', '/openid4vp/request', { body });
  }
  /** The request object a wallet fetches (the `request_uri`). */
  presentationRequest(id: string) {
    return this.request('get', '/openid4vp/request/{id}', { path: { id }, auth: 'none' });
  }
  /** The wallet side: submit the presentation. */
  submitPresentation(id: string, body: RequestBody<Operation<'post', '/openid4vp/response/{id}'>>) {
    return this.request('post', '/openid4vp/response/{id}', { path: { id }, body, auth: 'none' });
  }
  /** What the wallet presented, once it has. */
  presentationResult(id: string) {
    return this.request('get', '/openid4vp/result/{id}', { path: { id } });
  }

  // ---- W3C VC-API ----
  /** Operator action. Issue a credential through the VC-API issuer interface. */
  vcIssue(body: RequestBody<Operation<'post', '/credentials/issue'>>) {
    return this.request('post', '/credentials/issue', { body, auth: 'operator' });
  }
  /** Verify a Verifiable Credential (JWT or Data Integrity) through the VC-API verifier interface. */
  vcVerify(body: RequestBody<Operation<'post', '/credentials/verify'>>) {
    return this.request('post', '/credentials/verify', { body });
  }
  /** Verify a Verifiable Presentation through the VC-API verifier interface. */
  vpVerify(body: RequestBody<Operation<'post', '/presentations/verify'>>) {
    return this.request('post', '/presentations/verify', { body });
  }

  // ---- discovery ----
  /** This deployment's DID document (`did:web`). */
  didDocument() {
    return this.request('get', '/.well-known/did.json', { auth: 'none' });
  }
  /** The DID document for one country's issuer key. */
  didDocumentFor(countryCode: string) {
    return this.request('get', '/.well-known/did/{countryCode}.json', { path: { countryCode }, auth: 'none' });
  }
  /** A Bitstring Status List credential, for offline revocation checks. */
  statusList(file: string) {
    return this.request('get', '/.well-known/status/{file}', { path: { file }, auth: 'none' });
  }
  /** OpenID Connect discovery for the SSO provider mounted under /oidc. */
  oidcDiscovery() {
    return this.request('get', '/oidc/.well-known/openid-configuration', { auth: 'none' });
  }

  // ---- internals ----
  private async send(
    method: string,
    template: string,
    opts: {
      path?: Record<string, string | number>;
      query?: Record<string, unknown>;
      body?: unknown;
      auth?: Auth;
      headers?: Record<string, string>;
      accept?: string;
    },
  ): Promise<unknown> {
    // Parameter names are identifiers; the bounded class keeps the scan linear.
    const path = template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name: string) => {
      const value = opts.path?.[name];
      if (value === undefined) throw new Error(`Missing path parameter "${name}" for ${template}`);
      return encodeURIComponent(String(value));
    });
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) v.forEach((item) => q.append(k, String(item)));
      else q.set(k, String(v));
    }
    const qs = q.toString();

    const headers: Record<string, string> = { accept: opts.accept ?? 'application/json' };
    if (opts.body !== undefined) headers['content-type'] = 'application/json';
    this.applyAuth(headers, opts.auth ?? 'auto');
    Object.assign(headers, opts.headers);

    const res = await this.doFetch(`${this.baseUrl}${path}${qs ? `?${qs}` : ''}`, {
      method: method.toUpperCase(),
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    const isJson = (res.headers.get('content-type') ?? '').includes('json');
    let parsed: unknown = text;
    if (isJson || headers.accept === 'application/json') {
      try {
        parsed = text ? JSON.parse(text) : undefined;
      } catch {
        parsed = text;
      }
    }
    if (!res.ok) throw new OpenResidencyError(res.status, parsed);
    return parsed;
  }

  private applyAuth(headers: Record<string, string>, auth: Auth) {
    if (auth === 'none') return;
    if (typeof auth === 'object') {
      if ('bearer' in auth) headers['authorization'] = `Bearer ${auth.bearer}`;
      else Object.assign(headers, auth.headers);
      return;
    }
    // Preference order matches how much the deployment can tell about the caller:
    // an operator key or SSO token names a person; the shared key names nobody.
    if (this.operatorKey) {
      headers['x-operator-key'] = this.operatorKey;
    } else if (this.operatorToken) {
      headers['authorization'] = `Bearer ${this.operatorToken}`;
    } else if (this.adminKey) {
      headers['x-admin-key'] = this.adminKey;
    } else if (auth === 'operator') {
      throw new Error(
        'This endpoint requires operator authentication: set operatorKey (preferred), ' +
          'operatorToken, or the legacy adminKey in ClientOptions',
      );
    }
  }
}
