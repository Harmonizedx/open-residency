/**
 * OpenResidency Interoperability SDK.
 *
 * A small, dependency-free typed client for the OpenResidency API. Uses the global
 * fetch (Node 18+ or any browser). Every method maps one-to-one to an endpoint in
 * docs/openapi.yaml, so a sector service (Health, Tax, ...) or a partner system can
 * integrate without hand-writing HTTP calls.
 */

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

  // ---- identity ----
  identityChallenge(countryCode: string, identifiers: Record<string, string>) {
    return this.post<{ challengeRequired: boolean; challengeRef?: string; channel?: string }>(
      '/identity/challenge',
      { countryCode, identifiers },
    );
  }
  verifyIdentity(req: IdentityVerifyRequest) {
    return this.post<IdentityVerifyResponse>('/identity/verify', req);
  }

  // ---- residency ----
  countries() {
    return this.get<
      Array<{ countryCode: string; countryName: string; provider: string; inputs: unknown[] }>
    >('/residency/countries');
  }
  /** Operator action: needs the `registrar` role. */
  issueResidency(req: IssueRequest) {
    return this.post<IssueResult>('/residency/issue', req, true);
  }
  residencyStatus(residentId: string) {
    return this.get<ResidencyStatus>(`/residency/${encodeURIComponent(residentId)}`);
  }
  verifyCredential(credential: string, offline = false) {
    return this.post<CredentialVerifyOutcome>('/residency/verify', { credential, offline });
  }
  /** Operator action: needs the `revoker` role. */
  revokeResidency(residentId: string) {
    return this.post<{ revoked: boolean }>(
      `/residency/revoke/${encodeURIComponent(residentId)}`,
      {},
      true,
    );
  }

  // ---- consent ----
  // The consent routes are operator-guarded server-side (support role), so they carry
  // credentials like the admin ones. They previously did not, and 401'd.
  listConsents(residentId: string) {
    return this.get<{ residentId: string; consents: ConsentRecord[] }>(
      `/consent/resident/${encodeURIComponent(residentId)}`,
      true,
    );
  }
  grantConsent(req: {
    residentId: string;
    relyingParty: string;
    purpose: string;
    scopes: string[];
    relyingPartyName?: string;
    validityDays?: number;
  }) {
    return this.post<{ consent: ConsentRecord; receipt: string }>('/consent/grant', req, true);
  }
  revokeConsent(id: string) {
    return this.post<{ consent: ConsentRecord }>(
      `/consent/${encodeURIComponent(id)}/revoke`,
      {},
      true,
    );
  }

  // ---- admin (operator-authenticated) ----
  listResidents(params: { countryCode?: string; limit?: number; offset?: number } = {}) {
    const q = new URLSearchParams();
    if (params.countryCode) q.set('countryCode', params.countryCode);
    if (params.limit != null) q.set('limit', String(params.limit));
    if (params.offset != null) q.set('offset', String(params.offset));
    return this.get<{ total: number; residents: ResidencyStatus[] }>(
      `/admin/residents?${q.toString()}`,
      true,
    );
  }
  auditLog(params: { limit?: number; offset?: number; target?: string } = {}) {
    const q = new URLSearchParams();
    if (params.limit != null) q.set('limit', String(params.limit));
    if (params.offset != null) q.set('offset', String(params.offset));
    if (params.target) q.set('target', params.target);
    return this.get<{ count: number; events: AuditEvent[] }>(`/audit?${q.toString()}`, true);
  }
  verifyAuditChain() {
    return this.get<{ ok: boolean; length: number; brokenAtSeq?: number }>('/audit/verify', true);
  }

  // ---- discovery ----
  oidcDiscovery() {
    return this.get<Record<string, unknown>>('/oidc/.well-known/openid-configuration');
  }

  // ---- internals ----
  private async get<T>(path: string, admin = false): Promise<T> {
    return this.request<T>('GET', path, undefined, admin);
  }
  private async post<T>(path: string, body: unknown, admin = false): Promise<T> {
    return this.request<T>('POST', path, body, admin);
  }
  private async request<T>(method: string, path: string, body?: unknown, admin = false): Promise<T> {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (admin) {
      // Preference order matches how much the deployment can tell about the caller:
      // an operator key or SSO token names a person; the shared key names nobody.
      if (this.operatorKey) {
        headers['x-operator-key'] = this.operatorKey;
      } else if (this.operatorToken) {
        headers['authorization'] = `Bearer ${this.operatorToken}`;
      } else if (this.adminKey) {
        headers['x-admin-key'] = this.adminKey;
      } else {
        throw new Error(
          'This endpoint requires operator authentication: set operatorKey (preferred), ' +
            'operatorToken, or the legacy adminKey in ClientOptions',
        );
      }
    }
    const res = await this.doFetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    const parsed = text ? JSON.parse(text) : undefined;
    if (!res.ok) throw new OpenResidencyError(res.status, parsed);
    return parsed as T;
  }
}
