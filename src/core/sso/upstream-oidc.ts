// SPDX-License-Identifier: Apache-2.0
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  SignJWT,
  jwtVerify,
  importPKCS8,
  createLocalJWKSet,
  compactDecrypt,
  decodeProtectedHeader,
  JWK,
  JWTPayload,
} from 'jose';
import { AssuranceLevel } from '../foundational/types';
import { ApplicantBinding } from '../proofing/binding';
import { tokenizeSubject } from '../foundational/util';

/**
 * Signing in a resident at an EXTERNAL OpenID Provider.
 *
 * Everything else in this system points the other way: this deployment IS the provider,
 * and relying parties come to it. But a jurisdiction whose residents already have a
 * national identity provider -- a MOSIP eSignet instance, a national eID, any conformant
 * OP -- should not ask those residents to prove themselves twice. Delegating that first
 * authentication is what makes the residency record something a resident can claim rather
 * than something an operator must key in for them.
 *
 * What arrives from a successful upstream sign-in is stronger than a registry lookup, and
 * the difference is the point. A lookup says "this identity record exists"; an upstream
 * authentication says "the source itself just confirmed the owner was present". That is
 * `authoritative_authentication` in the binding model -- the strongest binding rank there
 * is -- and it is why this belongs next to the proofing code rather than in a generic HTTP
 * client somewhere.
 *
 * SPEAKS THE STANDARD, NAMES NO VENDOR. There is no eSignet-specific branch here, exactly
 * as there is no `if (wallet === 'inji')` in the issuance path. eSignet is the OP most
 * likely to be on the other end and the strictest about several things -- `private_key_jwt`
 * is its only client authentication method, its userinfo response is a signed-then-
 * encrypted nested JWT, and its `sub` is pairwise per relying party -- so supporting it
 * properly means supporting the strict end of the standard. A deployment describes its OP
 * in config; nothing here knows which one it is.
 */

/** How an upstream `acr` value maps onto what this deployment will believe. */
export interface UpstreamAcrMapping {
  /** The upstream acr, verbatim (e.g. `mosip:idp:acr:biometrics`). */
  acr: string;
  /**
   * The assurance this deployment credits a sign-in with that acr.
   *
   * There is no default and no inferred ordering. Only the deployer knows what their OP's
   * "password" or "generated-code" actually establishes about the person, and this value
   * reaches every relying party as `assurance_level` -- so an unmapped acr is refused
   * rather than quietly credited.
   */
  assurance: AssuranceLevel;
}

export interface UpstreamOidcConfig {
  /** The OP's issuer identifier. Must match the `iss` of its id_token exactly. */
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  /**
   * The OP's signing keys, pinned.
   *
   * Pinned rather than fetched from `jwks_uri` for the same reason JSON-LD contexts are
   * pinned: whoever answers for that URL at verification time decides which signatures we
   * believe. A deployment that must track a rotating OP can refresh these out of band and
   * restart; that is a slower operation than a live fetch and a far smaller trust surface.
   */
  jwks: JWK[];
  clientId: string;
  redirectUri: string;
  /** `openid` is always sent; anything here is added to it. */
  scopes?: string[];
  /** Requested acr values, in preference order, sent as a space-separated list. */
  acrValues?: string[];
  /** What each acr the OP may return is worth here. An acr not listed is refused. */
  acrMapping: UpstreamAcrMapping[];
  /**
   * The RP's private key for `private_key_jwt` client authentication, as PKCS#8 PEM read
   * from this environment variable. Never the key itself: config is reviewed, printed and
   * committed, and a private key must not be any of those things.
   */
  clientAssertionKeyEnv: string;
  /** JWS algorithm for the client assertion. eSignet advertises RS256 only. */
  clientAssertionAlg?: string;
  /**
   * The RP's private key for DECRYPTING a nested-JWT userinfo response, if the OP encrypts
   * one. Same rule: an env var name, not a key. Absent means we expect an unencrypted
   * response and will refuse an encrypted one rather than guess at a key.
   */
  userinfoDecryptionKeyEnv?: string;
  /** Dot-free claim mapping: upstream claim name -> our field. */
  claimMapping?: Partial<Record<UpstreamIdentityField, string>>;
  /** Clock skew tolerated when validating token times. */
  clockToleranceSeconds?: number;
  timeoutMs?: number;
}

export type UpstreamIdentityField =
  | 'fullName'
  | 'givenName'
  | 'familyName'
  | 'dateOfBirth'
  | 'gender'
  | 'phone'
  | 'email'
  | 'photo'
  | 'addressHint';

/** Server-side state for one in-flight authorization, never given to the browser. */
export interface PendingUpstreamAuth {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: string;
}

export interface PendingUpstreamAuthStore {
  put(auth: PendingUpstreamAuth): Promise<void>;
  /**
   * Fetch and DELETE in one step.
   *
   * Single-use is the property that makes `state` a CSRF defence rather than decoration: a
   * replayed callback must find nothing. Implementations backed by a database should do
   * this as one atomic delete-returning, not a read followed by a write.
   */
  take(state: string): Promise<PendingUpstreamAuth | null>;
}

export class InMemoryPendingUpstreamAuthStore implements PendingUpstreamAuthStore {
  private byState = new Map<string, PendingUpstreamAuth>();
  async put(auth: PendingUpstreamAuth): Promise<void> {
    this.byState.set(auth.state, auth);
  }
  async take(state: string): Promise<PendingUpstreamAuth | null> {
    const found = this.byState.get(state);
    this.byState.delete(state);
    return found ?? null;
  }
}

export interface UpstreamLoginStart {
  /** Where to send the resident's browser. */
  authorizationUrl: string;
  state: string;
}

export interface UpstreamIdentity {
  /**
   * HMAC of the upstream subject under the deployment pepper. Never the raw `sub`.
   *
   * NOT a residency `subjectRef`, and deliberately not named like one (ADR-0010). The OP's
   * `sub` is pairwise per relying party, so this answers "the same session subject at this
   * OP as last time?" and cannot answer "the same person the register already holds?" — a
   * pairwise subject is by construction unlinkable to anything outside the relationship
   * that issued it. Storing it as a record's identity would produce a reference no other
   * enrolment channel could reproduce.
   */
  authenticationRef: string;
  fullName?: string;
  givenName?: string;
  familyName?: string;
  dateOfBirth?: string;
  gender?: string;
  phone?: string;
  email?: string;
  photo?: string;
  addressHint?: string;
}

export interface UpstreamLoginResult {
  authenticated: boolean;
  identity?: UpstreamIdentity;
  /** The acr the OP reported, verbatim, for the audit trail. */
  acr?: string;
  assurance?: AssuranceLevel;
  binding?: ApplicantBinding;
  reason?: string;
}

const DEFAULT_CLOCK_TOLERANCE = 60;

/** Constant-time string comparison, for values an attacker can vary. */
function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

const base64url = (b: Buffer): string => b.toString('base64url');

/**
 * Refuse a declared-but-unusable upstream provider, at boot.
 *
 * Config that is accepted and then quietly does nothing is the failure this guards against:
 * a jurisdiction points `upstreamOidc` at its national IdP, watches it validate, and learns
 * months later — from the first resident who cannot sign in — that a key was never set. The
 * keys are named as environment variables rather than inlined, so their presence cannot be
 * checked by the schema and has to be checked here.
 *
 * Throws with the variable's own name, because "set OIDC_CLIENT_KEY" is actionable and
 * "upstream misconfigured" is not.
 */
export function assertUpstreamOidcUsable(
  cfg: UpstreamOidcConfig,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!env[cfg.clientAssertionKeyEnv]) {
    throw new Error(
      `upstreamOidc is configured but ${cfg.clientAssertionKeyEnv} is not set. ` +
        'private_key_jwt is the only client authentication eSignet accepts, so without that ' +
        'key no token request can be signed and no resident could ever sign in. Set it, or ' +
        'remove the upstreamOidc block.',
    );
  }
  if (cfg.userinfoDecryptionKeyEnv && !env[cfg.userinfoDecryptionKeyEnv]) {
    throw new Error(
      `upstreamOidc declares userinfoDecryptionKeyEnv=${cfg.userinfoDecryptionKeyEnv} but it ` +
        'is not set. Declaring it says the provider encrypts userinfo; without the key that ' +
        'response cannot be opened.',
    );
  }
}

export class UpstreamOidcClient {
  constructor(
    private cfg: UpstreamOidcConfig,
    private pending: PendingUpstreamAuthStore,
    private pepper: string = process.env.SUBJECT_PEPPER ?? 'dev-pepper',
    private fetchImpl: typeof fetch = fetch,
  ) {
    if (!cfg.acrMapping.length) {
      throw new Error(
        'upstream OIDC needs at least one acrMapping entry: what an upstream sign-in is ' +
          'worth here is a deployment decision, and there is no safe default for it',
      );
    }
    if (!cfg.jwks.length) {
      throw new Error('upstream OIDC needs the provider\'s signing keys pinned in jwks');
    }
  }

  /**
   * Begin a sign-in: build the authorization URL and remember what must come back.
   *
   * PKCE is used unconditionally. The RP authenticates to the token endpoint with a signed
   * assertion, so an intercepted code is not by itself redeemable -- but PKCE costs one
   * hash, and "not redeemable by anyone who cannot also sign as us" is a weaker statement
   * than "not redeemable without the verifier we never sent anywhere".
   */
  async beginLogin(): Promise<UpstreamLoginStart> {
    const state = base64url(randomBytes(32));
    const nonce = base64url(randomBytes(32));
    const codeVerifier = base64url(randomBytes(32));
    const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());

    await this.pending.put({
      state,
      nonce,
      codeVerifier,
      createdAt: new Date().toISOString(),
    });

    const url = new URL(this.cfg.authorizationEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.cfg.clientId);
    url.searchParams.set('redirect_uri', this.cfg.redirectUri);
    url.searchParams.set(
      'scope',
      ['openid', ...(this.cfg.scopes ?? [])].filter((s, i, a) => a.indexOf(s) === i).join(' '),
    );
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (this.cfg.acrValues?.length) {
      url.searchParams.set('acr_values', this.cfg.acrValues.join(' '));
    }

    return { authorizationUrl: url.toString(), state };
  }

  /**
   * Complete a sign-in from the redirect back.
   *
   * Fails closed on everything: an unknown `state`, a mismatched `nonce`, an id_token this
   * OP did not sign, an acr the deployment never mapped. Each returns a reason rather than
   * throwing, because a caller handling a browser redirect will turn a thrown error into a
   * 500 and a 500 into "try again", which is not what any of these mean.
   */
  async completeLogin(params: {
    code?: string;
    state?: string;
    error?: string;
  }): Promise<UpstreamLoginResult> {
    if (params.error) return { authenticated: false, reason: `UPSTREAM_ERROR:${params.error}` };
    if (!params.code || !params.state) {
      return { authenticated: false, reason: 'MISSING_CODE_OR_STATE' };
    }

    // Single-use by construction: take() deletes. A replayed callback finds nothing.
    const pending = await this.pending.take(params.state);
    if (!pending) return { authenticated: false, reason: 'UNKNOWN_STATE' };
    if (!safeEqual(pending.state, params.state)) {
      return { authenticated: false, reason: 'STATE_MISMATCH' };
    }

    let tokens: { id_token?: string; access_token?: string };
    try {
      tokens = await this.exchangeCode(params.code, pending.codeVerifier);
    } catch (e) {
      return { authenticated: false, reason: `TOKEN_REQUEST_FAILED:${(e as Error).message}` };
    }
    if (!tokens.id_token) return { authenticated: false, reason: 'NO_ID_TOKEN' };

    let claims: JWTPayload;
    try {
      claims = await this.verifyIdToken(tokens.id_token);
    } catch (e) {
      return { authenticated: false, reason: `ID_TOKEN_INVALID:${(e as Error).message}` };
    }

    // The nonce ties this id_token to the authorization request WE started. Without it, an
    // id_token issued for a different session at the same OP would be accepted here.
    if (typeof claims.nonce !== 'string' || !safeEqual(claims.nonce, pending.nonce)) {
      return { authenticated: false, reason: 'NONCE_MISMATCH' };
    }

    const acr = typeof claims.acr === 'string' ? claims.acr : undefined;
    const mapped = acr ? this.cfg.acrMapping.find((m) => m.acr === acr) : undefined;
    if (!mapped) {
      // An unmapped acr is not a weaker sign-in to be graded down; it is an authentication
      // method this deployment has said nothing about, and crediting it with anything would
      // be inventing policy at runtime.
      return { authenticated: false, reason: `UNMAPPED_ACR:${acr ?? 'none'}` };
    }

    const sub = typeof claims.sub === 'string' ? claims.sub : '';
    if (!sub) return { authenticated: false, reason: 'NO_SUBJECT' };

    // Claims may come from the id_token, and richer ones from userinfo when the OP offers
    // it. A userinfo failure is not fatal: the authentication already succeeded, and the
    // demographic detail is an enrichment.
    let profile: Record<string, unknown> = { ...claims };
    if (this.cfg.userinfoEndpoint && tokens.access_token) {
      try {
        const info = await this.fetchUserinfo(tokens.access_token);
        // The OP must not be able to switch subjects between the two responses.
        if (typeof info.sub === 'string' && !safeEqual(info.sub, sub)) {
          return { authenticated: false, reason: 'USERINFO_SUBJECT_MISMATCH' };
        }
        profile = { ...profile, ...info };
      } catch {
        // Deliberately swallowed: see above. The identity is still what the id_token said.
      }
    }

    return {
      authenticated: true,
      acr,
      assurance: mapped.assurance,
      identity: this.toIdentity(sub, profile),
      binding: {
        // The OP authenticated the owner; that is exactly what this binding means.
        method: 'authoritative_authentication',
        ref: typeof claims.jti === 'string' ? claims.jti : undefined,
        verifiedAt: new Date().toISOString(),
      },
    };
  }

  /** Exchange the code, authenticating with a signed assertion (`private_key_jwt`). */
  private async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<{ id_token?: string; access_token?: string }> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      code_verifier: codeVerifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await this.clientAssertion(),
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 8000);
    try {
      const res = await this.fetchImpl(this.cfg.tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP_${res.status}`);
      return (await res.json()) as { id_token?: string; access_token?: string };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * The `private_key_jwt` client assertion.
   *
   * `aud` is the token endpoint rather than the issuer. Both appear in the wild, and the
   * token endpoint is what RFC 7523 §3 describes and what eSignet checks; an assertion
   * audienced at the issuer is rejected by the OP with an error that says nothing useful.
   */
  private async clientAssertion(): Promise<string> {
    const pem = process.env[this.cfg.clientAssertionKeyEnv];
    if (!pem) {
      throw new Error(
        `client assertion key ${this.cfg.clientAssertionKeyEnv} is not set in the environment`,
      );
    }
    const alg = this.cfg.clientAssertionAlg ?? 'RS256';
    const key = await importPKCS8(pem, alg);
    return new SignJWT({})
      .setProtectedHeader({ alg })
      .setIssuer(this.cfg.clientId)
      .setSubject(this.cfg.clientId)
      .setAudience(this.cfg.tokenEndpoint)
      .setIssuedAt()
      .setExpirationTime('5m')
      // A unique jti per assertion: it is what lets the OP refuse a replayed one.
      .setJti(base64url(randomBytes(16)))
      .sign(key);
  }

  private async verifyIdToken(idToken: string): Promise<JWTPayload> {
    const jwks = createLocalJWKSet({ keys: this.cfg.jwks as any });
    const { payload } = await jwtVerify(idToken, jwks, {
      issuer: this.cfg.issuer,
      audience: this.cfg.clientId,
      clockTolerance: this.cfg.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE,
    });
    return payload;
  }

  /**
   * Fetch userinfo, which may be JSON, a signed JWT, or a signed-then-encrypted nested JWT.
   *
   * The nested case is the one worth spelling out: the OP encrypts to the RP's public key a
   * JWS that it signed. Decrypting yields a JWS, not claims -- and returning the decrypted
   * payload without verifying that inner signature would treat "someone encrypted this to
   * us" as "the OP asserted this", which is not the same statement at all.
   */
  private async fetchUserinfo(accessToken: string): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 8000);
    let raw: string;
    let contentType: string;
    try {
      const res = await this.fetchImpl(this.cfg.userinfoEndpoint!, {
        headers: { authorization: `Bearer ${accessToken}` },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP_${res.status}`);
      contentType = res.headers.get('content-type') ?? '';
      raw = await res.text();
    } finally {
      clearTimeout(timer);
    }

    if (contentType.includes('application/json')) {
      return JSON.parse(raw) as Record<string, unknown>;
    }

    let jws = raw.trim();
    // Five segments means JWE: it is encrypted to us and must be opened first.
    if (jws.split('.').length === 5) {
      const keyEnv = this.cfg.userinfoDecryptionKeyEnv;
      if (!keyEnv) {
        throw new Error(
          'userinfo response is encrypted but no userinfoDecryptionKeyEnv is configured',
        );
      }
      const pem = process.env[keyEnv];
      if (!pem) throw new Error(`userinfo decryption key ${keyEnv} is not set in the environment`);
      const header = decodeProtectedHeader(jws);
      const key = await importPKCS8(pem, String(header.alg ?? 'RSA-OAEP-256'));
      const { plaintext } = await compactDecrypt(jws, key);
      jws = Buffer.from(plaintext).toString('utf8').trim();
    }

    const jwks = createLocalJWKSet({ keys: this.cfg.jwks as any });
    const { payload } = await jwtVerify(jws, jwks, {
      issuer: this.cfg.issuer,
      clockTolerance: this.cfg.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE,
    });
    return payload as Record<string, unknown>;
  }

  /**
   * Map upstream claims onto our identity shape.
   *
   * The raw `sub` never leaves this method. It is HMAC'd under the deployment pepper by the
   * same helper every foundational adapter uses, so the residency store holds a reference
   * that is stable here and correlatable nowhere else -- which matters more than usual for
   * a pairwise `sub` the OP already scoped to us.
   */
  private toIdentity(sub: string, profile: Record<string, unknown>): UpstreamIdentity {
    const mapping: Partial<Record<UpstreamIdentityField, string>> = {
      fullName: 'name',
      givenName: 'given_name',
      familyName: 'family_name',
      dateOfBirth: 'birthdate',
      gender: 'gender',
      phone: 'phone_number',
      email: 'email',
      photo: 'picture',
      ...this.cfg.claimMapping,
    };

    const read = (field: UpstreamIdentityField): string | undefined => {
      const claim = mapping[field];
      if (!claim) return undefined;
      const value = profile[claim];
      return typeof value === 'string' && value.length ? value : undefined;
    };

    return {
      authenticationRef: tokenizeSubject(this.providerCode(), sub, this.pepper),
      fullName: read('fullName'),
      givenName: read('givenName'),
      familyName: read('familyName'),
      dateOfBirth: read('dateOfBirth'),
      gender: read('gender'),
      phone: read('phone'),
      email: read('email'),
      photo: read('photo'),
      addressHint: read('addressHint'),
    };
  }

  /**
   * The provider code that scopes the subject reference.
   *
   * Derived from the issuer so that two OPs configured in one deployment cannot produce
   * colliding references, and so a deployment that switches OP does not silently reuse the
   * old one's references for different people.
   */
  private providerCode(): string {
    return `oidc_${createHash('sha256').update(this.cfg.issuer).digest('hex').slice(0, 12)}`;
  }
}

