import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { join } from 'node:path';
import { JWK, exportJWK } from 'jose';
import { CountryConfig, loadCountryConfigs } from '../core/config/country-config';
import { ProviderRegistry } from '../core/foundational/registry';
import { KeyStore, IssuerKey } from '../core/credentials/keystore';
import { Pkcs11Signer } from '../core/credentials/signers/pkcs11-signer';
import { GcpKmsSigner } from '../core/credentials/signers/gcp-kms-signer';
import { AwsKmsSigner } from '../core/credentials/signers/aws-kms-signer';
import { VcIssuer } from '../core/credentials/vc-issuer';
import { LdpIssuer } from '../core/credentials/ldp-issuer';
import { residencyContextDocument } from '../core/credentials/jsonld/document-loader';
import { VcVerifier, TrustedIssuer } from '../core/credentials/vc-verifier';
import { applyFederation, FederatedIssuer } from '../core/credentials/federation';
import { buildDidWebDocument } from '../core/credentials/did';
import { ResidencyService } from '../core/residency/residency-service';
import { Oid4vciService } from '../core/oid4vci/oid4vci-service';
import { Oid4vpService } from '../core/oid4vp/oid4vp-service';
import { OtpService, OtpSender } from '../core/sso/otp';
import { SsoAuthService } from '../core/sso/sso-auth';
import { WebAuthnService } from '../core/sso/webauthn-service';
import { OperatorService } from '../core/operator/operator';
import { FederatedOperatorVerifier } from '../core/operator/federated';
import { OperatorSessions } from '../core/operator/session';
import { buildMessagingProvider } from '../core/messaging/providers';
import { MessagingOtpSender } from '../core/messaging/otp-sender';
import { ContactDirectory, MessagingProvider } from '../core/messaging/types';
import {
  EncryptedColumnContactDirectory,
  ExternalContactDirectory,
  NullContactDirectory,
} from '../core/messaging/contact-directory';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../core/oid4vp/vp-verifier';
import { AuditLog } from '../core/audit/audit-log';
import { ConsentService } from '../core/consent/consent';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOtpStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
  PrismaWebAuthnChallengeStore,
  PrismaWebAuthnCredentialStore,
} from '../prisma/prisma.service';
import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Everything the OperatorGuard needs to authenticate a member of staff, assembled once at
 * boot from `operatorAuth` in the default country config.
 */
export interface OperatorAuthContext {
  mode: 'oidc' | 'local' | 'sharedKey';
  operators: OperatorService;
  federated?: FederatedOperatorVerifier;
  sessions?: OperatorSessions;
  sharedKeyMatches(presented: string): boolean;
}

/**
 * Central wiring for the framework-agnostic core. Holds the loaded country configs,
 * the issuer key, the issuer/verifier, and the residency orchestration, and exposes
 * them to the thin Nest controllers.
 */
@Injectable()
export class PlatformService implements OnModuleDestroy {
  private readonly log = new Logger('Platform');
  private configs!: Map<string, CountryConfig>;
  private key!: IssuerKey;
  /** Public halves of keys rotated away from. Verified against, never signed with. */
  private retiredJwks: JWK[] = [];
  /** Set when the signing backend holds an external resource (an HSM session) to release. */
  private closeSigner?: () => Promise<void>;
  private registry!: ProviderRegistry;
  private issuer!: VcIssuer;
  private ldpIssuer!: LdpIssuer;
  private verifier!: VcVerifier;
  private residency!: ResidencyService;
  private oid4vci!: Oid4vciService;
  private oid4vp!: Oid4vpService;
  private vpVerifier!: VpVerifier;
  private ssoAuth!: SsoAuthService;
  private webauthn!: WebAuthnService;
  private audit!: AuditLog;
  private consent!: ConsentService;
  private platformIssuerDid!: string;
  private trust = new Map<string, TrustedIssuer>();
  private operatorAuth!: OperatorAuthContext;
  private messaging?: MessagingProvider;
  private contacts!: ContactDirectory;
  private pepper!: string;

  constructor(
    private store: PrismaResidencyStore,
    private auditStore: PrismaAuditStore,
    private consentStore: PrismaConsentStore,
    private oid4vciStore: PrismaOid4vciStore,
    private oid4vpStore: PrismaOid4vpStore,
    private otpStore: PrismaOtpStore,
    private operatorStore: PrismaOperatorStore,
    private webauthnChallengeStore: PrismaWebAuthnChallengeStore,
    private webauthnCredentialStore: PrismaWebAuthnCredentialStore,
  ) {}

  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    const dir = process.env.COUNTRY_CONFIG_DIR ?? join(process.cwd(), 'config/countries');
    this.configs = loadCountryConfigs(dir);
    this.log.log(`Loaded ${this.configs.size} country config(s): ${[...this.configs.keys()].join(', ')}`);

    this.key = await this.loadIssuerKey();
    this.retiredJwks = this.loadRetiredJwks();

    // Subject pepper: the HMAC key that makes a subjectRef non-reversible and
    // non-correlatable across deployments. Falling back silently is the worst case -- the
    // default is in the public source, so every subjectRef becomes reproducible by anyone
    // and the whole tokenization design is void. Warn as loudly as the issuer key does.
    const pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper';
    if (!process.env.SUBJECT_PEPPER) {
      this.log.warn(
        'No SUBJECT_PEPPER set: using the well-known dev pepper. Subject references are ' +
          'reproducible by anyone with the source. Do NOT use in production.',
      );
    }
    this.pepper = pepper;
    this.registry = new ProviderRegistry(pepper);
    this.issuer = new VcIssuer(this.key);
    this.ldpIssuer = new LdpIssuer(this.key);
    this.residency = new ResidencyService(
      this.registry,
      this.issuer,
      this.store,
      (cfg) => this.statusListUrl(cfg),
      this.ldpIssuer,
    );

    // OpenID4VCI: the standards-based issuance path that lets a citizen's own wallet
    // pull a credential bound to a key on their device.
    this.oid4vci = new Oid4vciService(
      { credentialIssuer: this.publicBaseUrl() },
      () => this.listConfigs(),
      (countryCode) => this.getConfig(countryCode),
      this.residency,
      this.store,
      this.oid4vciStore,
      this.key,
    );

    // Trust ourselves as an issuer for the verify endpoint (each config's issuerDid
    // maps to our public key). In a federation, other issuers' keys are added here.
    for (const cfg of this.configs.values()) {
      this.trust.set(cfg.credential.issuerDid, {
        did: cfg.credential.issuerDid,
        publicJwks: this.issuerPublicJwks(),
        statusLists: {},
      });
    }
    this.verifier = new VcVerifier(this.trust);

    // OpenID4VP: the presentation half. The VP verifier reuses the VC verifier -- and
    // therefore its status-list cache -- so a revoked resident is revoked whether the
    // credential arrives as a VC-JWT or as JSON-LD.
    const ldpTrust = new Map<string, VpTrustedIssuer>();
    for (const cfg of this.configs.values()) {
      ldpTrust.set(cfg.credential.issuerDid, {
        did: cfg.credential.issuerDid,
        publicKeyObjects: this.issuerPublicJwks().map(keyObjectFromJwk),
      });
    }
    // Federation: add trusted PEER issuers (other states / a national umbrella) to the
    // same trust maps that hold our own key, so a residency credential from a federated
    // issuer verifies here with no change to the verification path. Deployment-wide, read
    // from the default config like the OIDC and presentation profiles.
    const federated = (this.listConfigs()[0]?.federation.trustedIssuers ?? []) as FederatedIssuer[];
    if (federated.length) {
      applyFederation(this.trust, ldpTrust, federated);
      this.log.log(
        `Federation: trusting ${federated.length} peer issuer(s): ` +
          federated.map((f) => f.name ?? f.did).join(', '),
      );
    }

    this.vpVerifier = new VpVerifier(this.verifier, ldpTrust);
    // OpenID4VP is deployment-wide (a presentation request names no country), so its
    // profile is read from the default -- that is, the first -- country config.
    const defaultCfg = this.listConfigs()[0];
    this.oid4vp = new Oid4vpService(
      {
        baseUrl: this.publicBaseUrl(),
        // The verifier identifies itself by DID so a wallet can resolve our key and check
        // the request object's signature without a PKI or a network round-trip.
        clientId: defaultCfg?.credential.issuerDid ?? 'did:web:openresidency.example',
        clientName: defaultCfg?.credential.issuerName ?? 'OpenResidency Verifier',
        requestTtlSeconds: defaultCfg?.presentation.requestTtlSeconds ?? 300,
        query: defaultCfg?.presentation.query ?? ['dcql', 'presentation_definition'],
      },
      this.oid4vpStore,
      () => this.vpVerifier,
      this.key,
    );

    // Sign-in authentication: a Verifiable Presentation as the strong factor, a one-time
    // code as the fallback. Both halves of the fallback are configured, not stubbed --
    // the aggregator that carries the message, and the directory that turns a residentId
    // into a number to carry it to.
    this.contacts = this.buildContactDirectory(defaultCfg);
    this.messaging = this.buildMessaging(defaultCfg);
    const otp = new OtpService(this.otpStore, this.buildOtpSender(defaultCfg), () =>
      crypto.randomUUID(),
    );
    this.ssoAuth = new SsoAuthService(this.oid4vp, otp, this.store);

    // WebAuthn: a phishing-resistant passkey factor. rpId is the registrable domain of the
    // public base URL; the origin is that URL exactly. Registration is authorized by an
    // existing factor at the controller (see InteractionController), so a passkey can only
    // be enrolled for a resident whose one-time code or presentation the caller completed.
    const base = new URL(this.publicBaseUrl());
    this.webauthn = new WebAuthnService(
      { rpId: base.hostname, origin: base.origin, rpName: defaultCfg?.credential.issuerName ?? 'OpenResidency' },
      this.webauthnChallengeStore,
      this.webauthnCredentialStore,
    );

    // Operator identity for privileged routes.
    this.operatorAuth = this.buildOperatorAuth(defaultCfg);
    await this.bootstrapOperator();

    // Audit and consent frameworks.
    this.platformIssuerDid =
      process.env.PLATFORM_ISSUER_DID ??
      this.listConfigs()[0]?.credential.issuerDid ??
      'did:web:openresidency.example';
    this.audit = new AuditLog(this.auditStore);
    this.consent = new ConsentService(this.consentStore, this.key, this.platformIssuerDid);
  }

  // ---- messaging ----------------------------------------------------------

  /**
   * Where a resident's phone number comes from at send time.
   *
   * `none` is the default and disables OTP delivery outright. That is deliberate: the
   * previous behaviour was to "deliver" every code to the service log, which looks like a
   * working fallback factor and is not one. A deployment that has not decided where
   * contact data lives should have a sign-in fallback that is visibly off, not silently
   * broken.
   */
  private buildContactDirectory(cfg?: CountryConfig): ContactDirectory {
    const dir = cfg?.contactDirectory;
    if (!dir || dir.mode === 'none') return new NullContactDirectory();
    if (dir.mode === 'external') {
      this.log.log(`Contact directory: external (${dir.external!.baseUrl})`);
      return new ExternalContactDirectory(dir.external!);
    }
    if (!process.env.CONTACT_ENCRYPTION_KEY) {
      // Fail closed rather than run with a directory that can never decrypt anything: a
      // silently empty directory is indistinguishable from "this citizen has no phone".
      throw new Error(
        'contactDirectory.mode is `encrypted` but CONTACT_ENCRYPTION_KEY is not set. ' +
          'Generate one with `openssl rand -hex 32`.',
      );
    }
    this.log.log('Contact directory: encrypted column');
    return new EncryptedColumnContactDirectory((residentId) =>
      this.store.loadEncryptedContact(residentId),
    );
  }

  private buildMessaging(cfg?: CountryConfig): MessagingProvider | undefined {
    const m = cfg?.messaging;
    if (!m) {
      this.log.warn(
        'No messaging provider configured: one-time codes cannot be delivered, so the ' +
          'OTP sign-in fallback is disabled. Configure `messaging` in the country config.',
      );
      return undefined;
    }
    if (m.provider === 'LOG') {
      this.log.warn(
        'Messaging provider is LOG: one-time codes are written to the service log and ' +
          'NOT delivered. Development only.',
      );
    } else {
      this.log.log(`Messaging provider: ${m.provider}`);
    }
    return buildMessagingProvider({
      provider: m.provider,
      baseUrl: m.baseUrl,
      sender: m.sender,
      timeoutMs: m.timeoutMs,
      auth: m.auth,
      request: m.request,
    });
  }

  private buildOtpSender(cfg?: CountryConfig): OtpSender {
    const provider = this.messaging;
    const contacts = this.contacts;
    if (!provider) {
      // No aggregator: refuse to issue rather than pretend. The interaction controller
      // still answers the citizen identically either way, so this does not leak whether a
      // residency ID exists.
      return {
        async send(): Promise<{ channel: string }> {
          throw new Error('MESSAGING_NOT_CONFIGURED');
        },
      };
    }
    return new MessagingOtpSender(
      provider,
      contacts,
      cfg?.messaging?.otpTemplate,
      cfg?.credential.issuerName ?? 'OpenResidency',
    );
  }

  /** Send a non-OTP notification (USSD status replies). No-op when messaging is unconfigured. */
  async notify(residentId: string, body: string): Promise<boolean> {
    if (!this.messaging) return false;
    const to = await this.contacts.lookup(residentId);
    if (!to) return false;
    try {
      await this.messaging.send({ to, body, kind: 'notification' });
      return true;
    } catch (e) {
      this.log.warn(`Notification to resident ${residentId} failed: ${(e as Error).message}`);
      return false;
    }
  }

  messagingConfigured(): boolean {
    return !!this.messaging;
  }

  /** Which contact-storage policy this deployment runs, so enrolment keeps the right fields. */
  contactDirectoryMode(): 'none' | 'encrypted' | 'external' {
    return this.listConfigs()[0]?.contactDirectory.mode ?? 'none';
  }

  // ---- operator identity --------------------------------------------------

  private buildOperatorAuth(cfg?: CountryConfig): OperatorAuthContext {
    const conf = cfg?.operatorAuth ?? {
      mode: 'sharedKey' as const,
      issuerName: 'OpenResidency',
      local: { requireMfa: true, sessionTtlSeconds: 8 * 3600 },
    };
    const operators = new OperatorService(this.operatorStore, {
      requireMfa: conf.local.requireMfa,
      issuerName: conf.issuerName,
    });

    const ctx: OperatorAuthContext = {
      mode: conf.mode,
      operators,
      sharedKeyMatches: (presented: string) => {
        const required = process.env.ADMIN_API_KEY;
        if (!required) return false;
        // Hash both sides to a fixed length first: timingSafeEqual throws on a length
        // mismatch, which would itself leak the key's length.
        const a = createHash('sha256').update(presented).digest();
        const b = createHash('sha256').update(required).digest();
        return timingSafeEqual(a, b);
      },
    };

    if (conf.mode === 'oidc') {
      ctx.federated = new FederatedOperatorVerifier({
        issuer: conf.oidc!.issuer,
        audience: conf.oidc!.audience,
        roleClaim: conf.oidc!.roleClaim,
        nameClaim: conf.oidc!.nameClaim,
        roleMap: conf.oidc!.roleMap,
        jwksUri: conf.oidc!.jwksUri,
      });
      this.log.log(`Operator auth: OIDC (issuer ${conf.oidc!.issuer})`);
    } else if (conf.mode === 'local') {
      ctx.sessions = new OperatorSessions(
        this.key.signer,
        this.key.publicKey,
        this.publicBaseUrl(),
        conf.local.sessionTtlSeconds,
      );
      this.log.log(
        `Operator auth: local accounts (MFA ${conf.local.requireMfa ? 'required' : 'optional'})`,
      );
    } else {
      this.log.warn(
        'Operator auth: shared ADMIN_API_KEY. This carries no operator identity, so every ' +
          'privileged action audits to the same actor, there are no roles, and rotation ' +
          'requires a restart. Set operatorAuth.mode to `oidc` before government staff use ' +
          'this deployment.',
      );
    }
    return ctx;
  }

  /**
   * Create the first admin from the environment, once, if no operators exist.
   *
   * Without this there is no way into a `local` deployment: every operator-management
   * route requires an operator. The TOTP secret is logged exactly once, on the boot that
   * creates the account, because there is nowhere else for it to go -- and the account is
   * useless without it.
   */
  private async bootstrapOperator(): Promise<void> {
    const email = process.env.OPERATOR_BOOTSTRAP_EMAIL;
    const password = process.env.OPERATOR_BOOTSTRAP_PASSWORD;
    if (!email || !password) return;
    if ((await this.operatorAuth.operators.count()) > 0) return;
    const { totpSecret, totpUri } = await this.operatorAuth.operators.createOperator({
      email,
      displayName: email,
      roles: ['admin'],
      password,
    });
    this.log.warn(
      `Bootstrapped the first operator account ${email} with the admin role. ` +
        `Enrol this TOTP secret in an authenticator app now -- it is not shown again: ${totpSecret}`,
    );
    this.log.warn(`Enrolment URI: ${totpUri}`);
  }

  getOperatorAuth(): OperatorAuthContext {
    return this.operatorAuth;
  }

  /**
   * The HMAC key behind every pseudonym this deployment issues -- foundational subject
   * references and pairwise OIDC subjects alike. One pepper, so there is a single secret
   * to protect and a single rotation to reason about.
   */
  getSubjectPepper(): string {
    return this.pepper;
  }

  /**
   * The public origin of this deployment. It doubles as the OpenID4VCI Credential Issuer
   * Identifier, which is what a wallet's key proof must name in its `aud` -- so if this
   * is misconfigured, every proof is rejected as audience-mismatched.
   */
  publicBaseUrl(): string {
    return (process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000').replace(/\/$/, '');
  }

  statusListUrl(cfg: CountryConfig): string {
    return `${this.publicBaseUrl()}/.well-known/status/${cfg.countryCode.toLowerCase()}.json`;
  }

  /** The residency JSON-LD context document, published for external verifiers. */
  residencyContext(): unknown {
    return residencyContextDocument();
  }

  getConfig(countryCode: string): CountryConfig | undefined {
    return this.configs.get(countryCode.toUpperCase());
  }
  listConfigs(): CountryConfig[] {
    return [...this.configs.values()];
  }
  getResidency(): ResidencyService {
    return this.residency;
  }
  getOid4vci(): Oid4vciService {
    return this.oid4vci;
  }
  getOid4vp(): Oid4vpService {
    return this.oid4vp;
  }
  getSsoAuth(): SsoAuthService {
    return this.ssoAuth;
  }
  getWebAuthn(): WebAuthnService {
    return this.webauthn;
  }
  getLdpIssuer(): LdpIssuer {
    return this.ldpIssuer;
  }
  getVerifier(): VcVerifier {
    return this.verifier;
  }
  getStore(): PrismaResidencyStore {
    return this.store;
  }
  getAudit(): AuditLog {
    return this.audit;
  }
  getConsent(): ConsentService {
    return this.consent;
  }
  /** Release the HSM session, if the signing backend holds one. */
  async onModuleDestroy(): Promise<void> {
    if (!this.closeSigner) return;
    try {
      await this.closeSigner();
    } catch (e) {
      this.log.warn(`Failed to close the signing backend cleanly: ${(e as Error).message}`);
    }
  }

  getIssuerKey(): IssuerKey {
    return this.key;
  }

  /**
   * The private JWK the OIDC provider signs id_tokens and userinfo with.
   *
   * This is separate from the credential issuer key on purpose. `oidc-provider` signs
   * internally and accepts only literal private JWKs -- it has no hook for a remote
   * signer -- so the SSO layer fundamentally cannot run against an HSM-held key. Rather
   * than let that requirement drag the credential key back out of the HSM, the two get
   * separate keys with separate custody.
   *
   * That split is defensible on its own terms, not just as a workaround. An id_token
   * lives for minutes, is consumed by a fixed set of registered relying parties, and can
   * be rotated at will. A residency credential is verified offline by strangers, years
   * after issuance, and rotating its key means republishing trust anchors. Only the
   * second one actually needs never-exportable custody; holding the first in process
   * memory is a normal, recoverable risk.
   *
   * OIDC_SIGNING_JWK supplies it. Falling back to the issuer key is allowed only while
   * that key is itself in-process -- otherwise there is nothing to fall back to.
   */
  async oidcSigningJwk(): Promise<JWK> {
    const kid = process.env.OIDC_SIGNING_KID ?? 'oidc-key-1';
    const configured = process.env.OIDC_SIGNING_JWK;

    if (configured) {
      let jwk: JWK;
      try {
        jwk = JSON.parse(configured) as JWK;
      } catch {
        throw new Error('OIDC_SIGNING_JWK is not valid JSON.');
      }
      if (!(jwk as { d?: string }).d) {
        throw new Error('OIDC_SIGNING_JWK must be a PRIVATE JWK (no "d" component present).');
      }
      return { ...jwk, kid, alg: 'EdDSA', use: 'sig' };
    }

    if (!this.key.privateKey) {
      throw new Error(
        'The OIDC provider needs an exportable private key, but the issuer key is held by a ' +
          'remote signer (HSM/KMS) and cannot be exported. Set OIDC_SIGNING_JWK to give the ' +
          'SSO layer its own key, or disable the SSO module.',
      );
    }

    if (process.env.NODE_ENV === 'production') {
      this.log.warn(
        'No OIDC_SIGNING_JWK set: the SSO layer is signing id_tokens with the credential ' +
          'issuer key. That couples two very different lifetimes -- rotating the SSO key ' +
          'then means rotating the credential trust anchor. Give SSO its own key.',
      );
    }
    return { ...(await exportJWK(this.key.privateKey)), kid: this.key.kid, alg: 'EdDSA', use: 'sig' };
  }

  /**
   * Every public key this deployment has signed with: the active one, then retired ones.
   *
   * This is what goes into the trust list and the published DID document, so a
   * credential signed before the last rotation still verifies.
   */
  issuerPublicJwks(): JWK[] {
    return [this.key.publicJwk, ...this.retiredJwks];
  }

  /**
   * Public halves of keys this deployment has rotated away from, via ISSUER_RETIRED_JWKS
   * (a JSON array of public JWKs, each with its `kid`).
   *
   * Rotation is otherwise a data-loss event for citizens: their credentials remain
   * cryptographically sound but become unverifiable, and the only visible symptom is
   * residents being turned away at service desks with "untrusted issuer". Retired keys
   * are published and trusted for verification; only the active key ever signs.
   */
  private loadRetiredJwks(): JWK[] {
    const raw = process.env.ISSUER_RETIRED_JWKS;
    if (!raw) return [];

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('ISSUER_RETIRED_JWKS is not valid JSON (expected an array of public JWKs).');
    }
    if (!Array.isArray(parsed)) {
      throw new Error('ISSUER_RETIRED_JWKS must be a JSON array of public JWKs.');
    }

    return parsed.map((entry, i) => {
      const jwk = entry as JWK;
      if (!jwk || typeof jwk !== 'object' || !jwk.kty || !jwk.x) {
        throw new Error(`ISSUER_RETIRED_JWKS[${i}] is not a public JWK.`);
      }
      // A private key here would mean retired signing material is being shipped around in
      // config, which is the opposite of what retiring a key is for.
      if ((jwk as { d?: string }).d) {
        throw new Error(
          `ISSUER_RETIRED_JWKS[${i}] contains private key material ("d"). Publish public keys only.`,
        );
      }
      if (!jwk.kid) {
        throw new Error(
          `ISSUER_RETIRED_JWKS[${i}] has no "kid". Retired keys are selected by kid, so it is required.`,
        );
      }
      if (jwk.kid === this.key.kid) {
        throw new Error(
          `ISSUER_RETIRED_JWKS[${i}] reuses the active kid "${jwk.kid}". A retired key must have a distinct kid.`,
        );
      }
      return jwk;
    });
  }

  /**
   * Resolve the issuer signing key from the configured custody backend.
   *
   * `ISSUER_KEY_BACKEND` selects it:
   *   dev    -- generate an ephemeral key in-process. Refused when NODE_ENV=production.
   *   env    -- import the JWK in ISSUER_PRIVATE_JWK. Real key material in this process.
   *   pkcs11 -- sign inside an HSM. The private key never enters this process.
   *   gcpkms -- sign in Google Cloud KMS. Likewise never exports the key.
   *   awskms -- sign in AWS KMS. Likewise never exports the key.
   *
   * Further backends slot in the same way: construct an adapter implementing `Signer`
   * and hand it to `KeyStore.fromSigner`. Nothing else in the codebase changes.
   *
   * On Azure, use `pkcs11`: Dedicated HSM and Luna Cloud HSM are Thales Luna appliances
   * that expose a PKCS#11 library (untested here -- the interface matches, but nobody has
   * run it against a real appliance). Azure Key Vault and Managed HSM cannot be used at
   * all -- they have no Ed25519 curve, and their sign API takes a digest rather than a
   * message, which PureEdDSA cannot accept.
   *
   * Verification differs by backend and the difference matters: `pkcs11` is tested end to
   * end against SoftHSM; `gcpkms` and `awskms` are tested against mock services, which
   * covers the wire protocol but not IAM, endpoints, or credential chains.
   *
   * The default is `env` when a JWK is present and `dev` otherwise, so existing
   * deployments and local development both keep working without new configuration.
   *
   * Production fails closed. Previously a missing ISSUER_PRIVATE_JWK logged a warning
   * and minted a throwaway key: the service came up healthy and issued credentials
   * signed by a key that disappears on restart and that no verifier trusts. Every
   * credential issued in that window is silently worthless, and nothing surfaces it.
   * A refusal to boot is the strictly better failure.
   */
  private async loadIssuerKey(): Promise<IssuerKey> {
    const kid = process.env.ISSUER_KID ?? 'issuer-key-1';
    const jwkEnv = process.env.ISSUER_PRIVATE_JWK;
    const production = process.env.NODE_ENV === 'production';
    const backend = (process.env.ISSUER_KEY_BACKEND ?? (jwkEnv ? 'env' : 'dev')).toLowerCase();

    /** A backend's required setting, or a message naming exactly what is missing. */
    const req = (name: string): string => {
      const value = process.env[name];
      if (!value) throw new Error(`ISSUER_KEY_BACKEND=${backend} requires ${name} to be set.`);
      return value;
    };

    switch (backend) {
      case 'env': {
        if (!jwkEnv) {
          throw new Error(
            'ISSUER_KEY_BACKEND=env but ISSUER_PRIVATE_JWK is not set. Supply the issuer ' +
              'private JWK, or set ISSUER_KEY_BACKEND=dev for local development.',
          );
        }
        let jwk: JWK;
        try {
          jwk = JSON.parse(jwkEnv) as JWK;
        } catch {
          throw new Error('ISSUER_PRIVATE_JWK is not valid JSON.');
        }
        if (production) {
          this.log.warn(
            'Issuer key loaded from ISSUER_PRIVATE_JWK: the private key is exportable and ' +
              'resident in this process. Acceptable only if the environment is sealed. ' +
              'Prefer an HSM/KMS-backed Signer, where the key cannot leave the device.',
          );
        }
        return KeyStore.fromJwk(jwk, kid);
      }

      case 'pkcs11': {
        const libraryPath = req('PKCS11_LIBRARY');
        const pin = req('PKCS11_PIN');
        const keyLabel = req('PKCS11_KEY_LABEL');
        const slotEnv = process.env.PKCS11_SLOT;
        const signer = await Pkcs11Signer.open({
          libraryPath,
          pin,
          keyLabel,
          kid,
          tokenLabel: process.env.PKCS11_TOKEN_LABEL,
          slot: slotEnv === undefined ? undefined : Number(slotEnv),
        });
        // Release the token cleanly on shutdown rather than leaving a logged-in session
        // pinned until the process is killed.
        this.closeSigner = () => signer.close();
        this.log.log(
          `Issuer key: PKCS#11 token, key "${keyLabel}" (kid ${signer.kid}). ` +
            'The private key stays in the HSM.',
        );
        return KeyStore.fromSigner(signer);
      }

      case 'gcpkms': {
        const keyName = req('GCP_KMS_KEY_NAME');
        const signer = await GcpKmsSigner.open({
          keyName,
          kid,
          baseUrl: process.env.GCP_KMS_BASE_URL,
        });
        this.log.log(
          `Issuer key: Google Cloud KMS, ${keyName} (kid ${signer.kid}). ` +
            'The private key stays in Cloud KMS.',
        );
        return KeyStore.fromSigner(signer);
      }

      case 'awskms': {
        const keyId = req('AWS_KMS_KEY_ID');
        const region = process.env.AWS_KMS_REGION ?? process.env.AWS_REGION;
        if (!region) {
          throw new Error(
            'ISSUER_KEY_BACKEND=awskms requires AWS_KMS_REGION (or AWS_REGION) to be set.',
          );
        }
        const signer = await AwsKmsSigner.open({
          keyId,
          region,
          kid,
          endpoint: process.env.AWS_KMS_ENDPOINT,
        });
        this.log.log(
          `Issuer key: AWS KMS, ${keyId} in ${region} (kid ${signer.kid}). ` +
            'The private key stays in KMS.',
        );
        return KeyStore.fromSigner(signer);
      }

      case 'dev': {
        if (production) {
          throw new Error(
            'Refusing to start: NODE_ENV=production with no issuer key configured. An ' +
              'ephemeral key would sign credentials that no verifier trusts and that break ' +
              'on restart. Set ISSUER_KEY_BACKEND and provide real key material.',
          );
        }
        this.log.warn(
          'No issuer key configured: generated an ephemeral dev key. Credentials signed ' +
            'with it are worthless outside this process. Do NOT use in production.',
        );
        return KeyStore.generate(kid);
      }

      default:
        throw new Error(
          `Unknown ISSUER_KEY_BACKEND "${backend}". Supported: pkcs11, gcpkms, awskms, ` +
            'env, dev. To add another backend, implement the Signer port in ' +
            'src/core/credentials/signer.ts and register it here.',
        );
    }
  }

  didDocument(countryCode: string): Record<string, unknown> | undefined {
    const cfg = this.getConfig(countryCode);
    if (!cfg) return undefined;
    return buildDidWebDocument(cfg.credential.issuerDid, this.issuerPublicJwks());
  }

  /** Refresh the verifier's cached status list for a country from the store. */
  async syncStatusList(cfg: CountryConfig): Promise<void> {
    const list = await this.store.loadStatusList(cfg.countryCode);
    const t = this.trust.get(cfg.credential.issuerDid);
    if (t) t.statusLists = { [this.statusListUrl(cfg)]: list };
  }
}
