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
  /** Admin key, required only for audit and admin endpoints. */
  adminKey?: string;
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
  private adminKey?: string;
  private doFetch: typeof fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.adminKey = opts.adminKey;
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
  issueResidency(req: IssueRequest) {
    return this.post<IssueResult>('/residency/issue', req);
  }
  residencyStatus(residentId: string) {
    return this.get<ResidencyStatus>(`/residency/${encodeURIComponent(residentId)}`);
  }
  verifyCredential(credential: string, offline = false) {
    return this.post<CredentialVerifyOutcome>('/residency/verify', { credential, offline });
  }
  revokeResidency(residentId: string) {
    return this.post<{ revoked: boolean }>(`/residency/revoke/${encodeURIComponent(residentId)}`, {});
  }

  // ---- consent ----
  listConsents(residentId: string) {
    return this.get<{ residentId: string; consents: ConsentRecord[] }>(
      `/consent/resident/${encodeURIComponent(residentId)}`,
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
    return this.post<{ consent: ConsentRecord; receipt: string }>('/consent/grant', req);
  }
  revokeConsent(id: string) {
    return this.post<{ consent: ConsentRecord }>(`/consent/${encodeURIComponent(id)}/revoke`, {});
  }

  // ---- admin (requires adminKey) ----
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
      if (!this.adminKey) throw new Error('This endpoint requires an adminKey in ClientOptions');
      headers['x-admin-key'] = this.adminKey;
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
