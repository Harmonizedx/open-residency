import { randomBytes, randomUUID } from 'node:crypto';
import {
  verifyRegistration,
  verifyAssertion,
  RegisteredCredential,
  RegistrationCeremony,
  AuthenticationCeremony,
  CeremonyExpectations,
} from './webauthn';

/**
 * WebAuthn orchestration: the registration and authentication ceremonies as a flow, on
 * top of the pure verification core (webauthn.ts) and two persistence ports.
 *
 * The security-critical property lives at REGISTRATION. A passkey is a possession factor,
 * so whoever registers one for a residentId can thereafter sign in as that resident.
 * Registration therefore must be authorized by an already-proven factor -- this service
 * only issues a registration challenge for a residentId the caller has ALREADY
 * authenticated (via the one-time code delivered to the resident's registered number, or a
 * Verifiable Presentation). The controller enforces that before calling startRegistration;
 * the honest security statement is: you can only enroll a passkey for a resident whose
 * existing factor you can complete.
 *
 * Authentication is the ordinary path: prove possession of a registered passkey. It is
 * phishing-resistant (the authenticator signs over the origin, which the core checks), so
 * it authenticates at AAL2 on its own -- unlike the one-time code.
 */

export interface WebAuthnChallengeRecord {
  id: string;
  residentId: string;
  /** base64url challenge bytes the ceremony must sign over. */
  challenge: string;
  /** 'register' or 'authenticate' -- a challenge is valid for one ceremony type only. */
  purpose: 'register' | 'authenticate';
  expiresAt: string;
  consumed: boolean;
  createdAt: string;
}

export interface WebAuthnChallengeStore {
  save(record: WebAuthnChallengeRecord): Promise<void>;
  findActive(id: string): Promise<WebAuthnChallengeRecord | null>;
  consume(id: string): Promise<void>;
}

export interface StoredCredential extends RegisteredCredential {
  id: string;
  residentId: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface WebAuthnCredentialStore {
  add(cred: StoredCredential): Promise<void>;
  /** Every credential registered to a resident (a resident may enroll several devices). */
  listForResident(residentId: string): Promise<StoredCredential[]>;
  findByCredentialId(credentialId: string): Promise<StoredCredential | null>;
  /** Persist the advanced signature counter after a successful assertion. */
  updateSignCount(credentialId: string, signCount: number, lastUsedAt: string): Promise<void>;
}

export interface RelyingPartyInfo {
  /** e.g. id.katsina.gov.ng -- the registrable domain the passkey is scoped to. */
  rpId: string;
  /** e.g. https://id.katsina.gov.ng -- the exact origin the browser must report. */
  origin: string;
  /** Shown by the authenticator UI. */
  rpName: string;
}

const CHALLENGE_TTL_SECONDS = 300;

export class WebAuthnService {
  constructor(
    private rp: RelyingPartyInfo,
    private challenges: WebAuthnChallengeStore,
    private credentials: WebAuthnCredentialStore,
    private now: () => number = () => Date.now(),
  ) {}

  private newChallenge(residentId: string, purpose: 'register' | 'authenticate'): WebAuthnChallengeRecord {
    const nowMs = this.now();
    return {
      id: randomUUID(),
      residentId,
      challenge: randomBytes(32).toString('base64url'),
      purpose,
      expiresAt: new Date(nowMs + CHALLENGE_TTL_SECONDS * 1000).toISOString(),
      consumed: false,
      createdAt: new Date(nowMs).toISOString(),
    };
  }

  /**
   * Begin registration for an ALREADY-AUTHENTICATED resident. The caller MUST have
   * verified an existing factor for `residentId` first -- this service does not itself
   * check that, because the proof lives in the interaction layer above it.
   *
   * Returns the PublicKeyCredentialCreationOptions a browser passes to
   * navigator.credentials.create(), plus the opaque challenge id to echo back.
   */
  async startRegistration(residentId: string): Promise<{
    challengeId: string;
    options: Record<string, unknown>;
  }> {
    const record = this.newChallenge(residentId, 'register');
    await this.challenges.save(record);

    const existing = await this.credentials.listForResident(residentId);
    return {
      challengeId: record.id,
      options: {
        challenge: record.challenge,
        rp: { id: this.rp.rpId, name: this.rp.rpName },
        // The user handle is the residentId. It is already the account key the RP knows;
        // it is not a national identifier and is not correlatable across relying parties.
        user: { id: Buffer.from(residentId).toString('base64url'), name: residentId, displayName: residentId },
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 }, // EdDSA
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        // Ask the authenticator to verify the user on-device (PIN/biometric); this is what
        // makes the resulting factor two-factor on its own (possession + inherence/knowledge).
        authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
        // Don't let the same device register twice for one resident.
        excludeCredentials: existing.map((c) => ({ type: 'public-key', id: c.credentialId })),
        timeout: CHALLENGE_TTL_SECONDS * 1000,
      },
    };
  }

  /** Complete registration: verify the attestation and persist the credential. */
  async finishRegistration(
    challengeId: string,
    residentId: string,
    ceremony: RegistrationCeremony,
  ): Promise<{ ok: true; credentialId: string } | { ok: false; reason: string }> {
    const record = await this.consumeChallenge(challengeId, residentId, 'register');
    if (!record.ok) return { ok: false, reason: record.reason };

    let registered: RegisteredCredential;
    try {
      registered = verifyRegistration(ceremony, this.expectations(record.challenge));
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }

    // Guard against re-binding a credential id that already exists (to anyone).
    if (await this.credentials.findByCredentialId(registered.credentialId)) {
      return { ok: false, reason: 'CREDENTIAL_ALREADY_REGISTERED' };
    }

    await this.credentials.add({
      ...registered,
      id: randomUUID(),
      residentId,
      createdAt: new Date(this.now()).toISOString(),
    });
    return { ok: true, credentialId: registered.credentialId };
  }

  /**
   * Begin authentication. The resident names their residentId (as with the one-time code),
   * and we return the credentials they may use plus a challenge to sign.
   */
  async startAuthentication(residentId: string): Promise<{
    challengeId: string;
    options: Record<string, unknown>;
  } | null> {
    const creds = await this.credentials.listForResident(residentId);
    if (creds.length === 0) return null; // no passkey enrolled; caller falls back to another factor

    const record = this.newChallenge(residentId, 'authenticate');
    await this.challenges.save(record);
    return {
      challengeId: record.id,
      options: {
        challenge: record.challenge,
        rpId: this.rp.rpId,
        allowCredentials: creds.map((c) => ({ type: 'public-key', id: c.credentialId })),
        userVerification: 'required',
        timeout: CHALLENGE_TTL_SECONDS * 1000,
      },
    };
  }

  /**
   * Complete authentication: verify the assertion against the stored credential, advance
   * the clone-detection counter, and return the authenticated residentId.
   */
  async finishAuthentication(
    challengeId: string,
    ceremony: AuthenticationCeremony,
  ): Promise<{ ok: true; residentId: string } | { ok: false; reason: string }> {
    const cred = await this.credentials.findByCredentialId(ceremony.credentialId);
    if (!cred) return { ok: false, reason: 'UNKNOWN_CREDENTIAL' };

    const record = await this.consumeChallenge(challengeId, cred.residentId, 'authenticate');
    if (!record.ok) return { ok: false, reason: record.reason };

    const result = verifyAssertion(ceremony, cred, this.expectations(record.challenge));
    if (!result.ok) return { ok: false, reason: result.reason ?? 'ASSERTION_FAILED' };

    await this.credentials.updateSignCount(
      cred.credentialId,
      result.newSignCount ?? cred.signCount,
      new Date(this.now()).toISOString(),
    );
    return { ok: true, residentId: cred.residentId };
  }

  private expectations(challenge: string): CeremonyExpectations {
    return { challenge, origin: this.rp.origin, rpId: this.rp.rpId, requireUserVerification: true };
  }

  private async consumeChallenge(
    challengeId: string,
    residentId: string,
    purpose: 'register' | 'authenticate',
  ): Promise<{ ok: true; challenge: string } | { ok: false; reason: string }> {
    const record = await this.challenges.findActive(challengeId);
    // A challenge is single-use, time-bound, purpose-bound, and resident-bound. Each of
    // these closes a distinct replay/confusion path, so all four are checked.
    if (!record) return { ok: false, reason: 'UNKNOWN_CHALLENGE' };
    if (record.consumed) return { ok: false, reason: 'CHALLENGE_ALREADY_USED' };
    if (record.purpose !== purpose) return { ok: false, reason: 'CHALLENGE_PURPOSE_MISMATCH' };
    if (record.residentId !== residentId) return { ok: false, reason: 'CHALLENGE_RESIDENT_MISMATCH' };
    if (new Date(record.expiresAt).getTime() < this.now()) return { ok: false, reason: 'CHALLENGE_EXPIRED' };
    // Consume before verifying, so a verification failure cannot be retried against the
    // same challenge with a tweaked assertion.
    await this.challenges.consume(record.id);
    return { ok: true, challenge: record.challenge };
  }
}

/** In-memory stores for tests and dev. */
export class InMemoryWebAuthnChallengeStore implements WebAuthnChallengeStore {
  private byId = new Map<string, WebAuthnChallengeRecord>();
  async save(r: WebAuthnChallengeRecord): Promise<void> {
    this.byId.set(r.id, { ...r });
  }
  async findActive(id: string): Promise<WebAuthnChallengeRecord | null> {
    return this.byId.get(id) ?? null;
  }
  async consume(id: string): Promise<void> {
    const r = this.byId.get(id);
    if (r) r.consumed = true;
  }
}

export class InMemoryWebAuthnCredentialStore implements WebAuthnCredentialStore {
  private byCredId = new Map<string, StoredCredential>();
  async add(c: StoredCredential): Promise<void> {
    this.byCredId.set(c.credentialId, { ...c });
  }
  async listForResident(residentId: string): Promise<StoredCredential[]> {
    return [...this.byCredId.values()].filter((c) => c.residentId === residentId);
  }
  async findByCredentialId(credentialId: string): Promise<StoredCredential | null> {
    return this.byCredId.get(credentialId) ?? null;
  }
  async updateSignCount(credentialId: string, signCount: number, lastUsedAt: string): Promise<void> {
    const c = this.byCredId.get(credentialId);
    if (c) {
      c.signCount = signCount;
      c.lastUsedAt = lastUsedAt;
    }
  }
}
