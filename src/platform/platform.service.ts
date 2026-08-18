// SPDX-License-Identifier: Apache-2.0
import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { join } from 'node:path';
import { JWK } from 'jose';
import { CountryConfig, loadCountryConfigs } from '../core/config/country-config';
import { ProviderRegistry } from '../core/foundational/registry';
import { IssuerKey } from '../core/credentials/keystore';
import { KeyCustody } from './key-custody';
import { BackgroundJobs } from './background-jobs';
import { ResidentMessaging } from './resident-messaging';
import { VcIssuer } from '../core/credentials/vc-issuer';
import { LdpIssuer } from '../core/credentials/ldp-issuer';
import { StatusListPublisher } from '../core/credentials/status-list-publisher';
import { residencyContextDocument } from '../core/credentials/jsonld/document-loader';
import { VcVerifier, TrustedIssuer } from '../core/credentials/vc-verifier';
import {
  applyFederation,
  FederatedIssuer,
  syncFederatedStatusLists,
} from '../core/credentials/federation';
import { buildDidWebDocument } from '../core/credentials/did';
import { ResidencyService } from '../core/residency/residency-service';
import { Oid4vciService } from '../core/oid4vci/oid4vci-service';
import { Oid4vpService } from '../core/oid4vp/oid4vp-service';
import { OtpService, OtpSender } from '../core/sso/otp';
import { SsoAuthService } from '../core/sso/sso-auth';
import {
  UpstreamOidcClient,
  UpstreamOidcConfig,
  assertUpstreamOidcUsable,
} from '../core/sso/upstream-oidc';
import { WebAuthnService } from '../core/sso/webauthn-service';
import { BiometricMatcher, buildBiometricMatcher } from '../core/proofing/biometric';
import { OperatorService } from '../core/operator/operator';
import { FederatedOperatorVerifier } from '../core/operator/federated';
import { OperatorSessions } from '../core/operator/session';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../core/oid4vp/vp-verifier';
import { AuditLog } from '../core/audit/audit-log';
import { ConsentService } from '../core/consent/consent';
import {
  LegalBasis,
  LegalBasisRegistry,
  legalBasesForDeployment,
} from '../core/consent/legal-basis';
import { AssuranceRegistry } from '../core/assurance/registry';
import { buildDefaultAssuranceRegistry } from '../core/assurance/profiles';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaLegalBasisStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOidcStore,
  PrismaRefusalStore,
  PrismaOtpStore,
  PrismaOperatorStore,
  PrismaResidencyStore,
  PrismaWebAuthnChallengeStore,
  PrismaWebAuthnCredentialStore,
  PrismaUpstreamAuthStore,
  PrismaAuditCheckpointStore,
} from '../prisma/prisma.service';
import { createHash, timingSafeEqual } from 'node:crypto';
import axios from 'axios';

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
  /** Federated peers, kept so their status lists can be re-synced after boot. */
  private federatedPeers: FederatedIssuer[] = [];

  private jobs?: BackgroundJobs;
  private msg!: ResidentMessaging;
  private readonly log = new Logger('Platform');
  private configs!: Map<string, CountryConfig>;
  private key!: IssuerKey;
  private registry!: ProviderRegistry;
  private issuer!: VcIssuer;
  private ldpIssuer!: LdpIssuer;
  private statusListPublisher!: StatusListPublisher;
  private verifier!: VcVerifier;
  private residency!: ResidencyService;
  private oid4vci!: Oid4vciService;
  private oid4vp!: Oid4vpService;
  private vpVerifier!: VpVerifier;
  private ssoAuth!: SsoAuthService;
  private webauthn!: WebAuthnService;
  private biometric!: BiometricMatcher | null;
  private audit!: AuditLog;
  private consent!: ConsentService;
  private legalBasisRegistry!: LegalBasisRegistry;
  private platformIssuerDid!: string;
  private trust = new Map<string, TrustedIssuer>();
  private operatorAuth!: OperatorAuthContext;
  /** Set only when the deployment configures an external OpenID Provider. */
  private upstreamOidc?: UpstreamOidcClient;
  private pepper!: string;
  private assurance: AssuranceRegistry = buildDefaultAssuranceRegistry();

  constructor(
    private store: PrismaResidencyStore,
    private auditStore: PrismaAuditStore,
    private consentStore: PrismaConsentStore,
    private legalBasisStore: PrismaLegalBasisStore,
    private oid4vciStore: PrismaOid4vciStore,
    private oid4vpStore: PrismaOid4vpStore,
    private oidcStore: PrismaOidcStore,
    private refusalStore: PrismaRefusalStore,
    private otpStore: PrismaOtpStore,
    private operatorStore: PrismaOperatorStore,
    private webauthnChallengeStore: PrismaWebAuthnChallengeStore,
    private webauthnCredentialStore: PrismaWebAuthnCredentialStore,
    private upstreamAuthStore: PrismaUpstreamAuthStore,
    private auditCheckpointStore: PrismaAuditCheckpointStore,
    private custody: KeyCustody,
  ) {}

  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    const dir = process.env.COUNTRY_CONFIG_DIR ?? join(process.cwd(), 'config/countries');
    this.configs = loadCountryConfigs(dir);
    this.log.log(`Loaded ${this.configs.size} country config(s): ${[...this.configs.keys()].join(', ')}`);

    // Custody decides where the private key lives and refuses to boot on an
    // unacceptable answer. This class only consumes the result.
    await this.custody.init();
    this.key = this.custody.getIssuerKey();

    // Subject pepper: the HMAC key that makes a subjectRef non-reversible and
    // non-correlatable across deployments. Falling back silently is the worst case -- the
    // default is in the public source, so every subjectRef becomes reproducible by anyone
    // and the whole tokenization design is void. Fail exactly as the issuer key does.
    //
    // A warning is not enough here. Foundational identifiers are low-entropy (an 11-digit
    // NIN is ~10^11 candidates), so a known pepper does not merely weaken the tokenization,
    // it makes every subjectRef in the register enumerable offline -- and the same pepper
    // derives pairwise OIDC subjects, so recovering it also collapses the cross-service
    // correlation defence. Both guarantees are ones a relying party is told they can depend
    // on, and neither can be restored after the fact: rotating the pepper invalidates every
    // stored subjectRef, so the register cannot recognise its own residents.
    if (!process.env.SUBJECT_PEPPER && process.env.NODE_ENV === 'production') {
      throw new Error(
        'Refusing to start: NODE_ENV=production with no SUBJECT_PEPPER set. The fallback ' +
          'pepper is published in this source, so every subjectRef would be reproducible by ' +
          'anyone and pairwise OIDC subjects would no longer be unlinkable. Set ' +
          'SUBJECT_PEPPER to a high-entropy deployment secret, and keep it: rotating it ' +
          'invalidates every subjectRef already stored.',
      );
    }
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
    this.statusListPublisher = new StatusListPublisher(this.ldpIssuer);
    this.residency = new ResidencyService(
      this.registry,
      this.issuer,
      this.store,
      (cfg) => this.statusListUrl(cfg),
      this.ldpIssuer,
      this.assurance,
      this.refusalStore,
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
      this.federatedPeers = federated;
    }

    this.vpVerifier = new VpVerifier(this.verifier, ldpTrust);
    // OpenID4VP is deployment-wide (a presentation request names no country), so its
    // profile is read from the default -- that is, the first -- country config.
    const defaultCfg = this.listConfigs()[0];
    // Sign-in at an EXTERNAL OpenID Provider (eSignet, a national eID, any conformant OP).
    //
    // Constructed only when the deployment declares one. Until this existed the config was
    // parsed and discarded: a jurisdiction could point `upstreamOidc` at its national IdP,
    // watch it validate at boot, and find no route had ever been mounted. Config that is
    // accepted and then ignored is worse than config that is refused.
    this.upstreamOidc = this.buildUpstreamOidc(defaultCfg);

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
    this.msg = new ResidentMessaging(this.store);
    this.msg.init(defaultCfg);
    const otp = new OtpService(this.otpStore, this.msg.buildOtpSender(defaultCfg), () =>
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

    // Biometric authority for the AAL3 step-up. Bring-your-own, deployment-wide; NONE by
    // default (no step-up offered). Fail-closed by contract -- see GenericHttpBiometricMatcher.
    this.biometric = buildBiometricMatcher(defaultCfg?.biometric);
    if (this.biometric) {
      this.log.log(`Biometric step-up: ${defaultCfg?.biometric.provider} authority configured.`);
    }

    // Federated peers' status lists. Fire-and-forget: another government's server is not
    // ours to depend on at boot, and an unsynced peer keeps the safe posture (presentations
    // of its credentials fail closed) rather than a dangerous one.
    void this.syncFederatedStatusLists().catch((e) =>
      this.log.warn(`Federation: initial status sync failed: ${(e as Error).message}`),
    );


    // Operator identity for privileged routes.
    this.operatorAuth = this.buildOperatorAuth(defaultCfg);
    await this.bootstrapOperator();

    // Audit and consent frameworks.
    this.platformIssuerDid =
      process.env.PLATFORM_ISSUER_DID ??
      this.listConfigs()[0]?.credential.issuerDid ??
      'did:web:openresidency.example';
    // Anchored: the chain alone cannot detect its own tail being cut, so the head is
    // periodically committed to and SIGNED with the issuer key. See core/audit/audit-log.ts.
    this.audit = new AuditLog(this.auditStore, this.auditCheckpointStore, this.key.signer);
    // Timers start only after everything they touch exists. Collected in one object so
    // shutdown is one call rather than three scattered clearIntervals.
    this.jobs = new BackgroundJobs({
      audit: this.audit,
      oidcStore: this.oidcStore,
      federatedPeers: () => this.federatedPeers,
      syncFederatedStatusLists: () => this.syncFederatedStatusLists(),
    });
    this.jobs.start();

    // ORCS §9: the controller and the Legal Basis Registry are deployment facts, declared
    // once. The controller falls back to the issuing authority's name -- the body issuing the
    // credential is processing the data to do it -- but a deployment where an agency issues
    // on the state's behalf should name the state in `dataProtection.controller`.
    const dpCfg = this.listConfigs()[0];
    const controller =
      dpCfg?.dataProtection.controller ?? dpCfg?.credential.issuerName ?? 'OpenResidency';
    this.legalBasisRegistry = new LegalBasisRegistry(
      legalBasesForDeployment({
        jurisdiction: dpCfg?.countryName ?? 'unspecified',
        controller,
        declared: dpCfg?.dataProtection.legalBases,
      }),
    );

    // Replay withdrawals. The registry is rebuilt from config on every boot, so without this a
    // repealed by-law would come back in force at the next restart and every consent citing it
    // would start authorising processing again.
    for (const d of await this.legalBasisStore.listDeactivations()) {
      const outcome = this.legalBasisRegistry.deactivate(d.id, {
        reason: d.deactivationReason,
        authority: d.deactivatedBy,
        at: d.deactivatedAt,
      });
      // A withdrawal for a basis the config no longer declares is not an error: the deployment
      // removed it, which is a stronger form of the same act. Anything else is worth saying out
      // loud, because it means a recorded withdrawal did not take effect.
      if (!outcome.ok && outcome.reason !== 'UNKNOWN_LEGAL_BASIS') {
        this.log.warn(`Could not replay withdrawal of legal basis ${d.id}: ${outcome.reason}`);
      }
    }
    this.consent = new ConsentService(this.consentStore, this.key, this.platformIssuerDid, {
      controller,
      processor: dpCfg?.dataProtection.processor,
      legalBases: this.legalBasisRegistry,
      defaultLegalBasisReference: dpCfg?.dataProtection.defaultLegalBasisReference,
    });
  }

  /** The Legal Basis Registry (ORCS §9), for the consent and legal-basis APIs. */
  getLegalBases(): LegalBasisRegistry {
    return this.legalBasisRegistry;
  }

  /** Make a withdrawal durable, so it survives a restart and reaches other instances. */
  async persistLegalBasisWithdrawal(basis: LegalBasis): Promise<void> {
    await this.legalBasisStore.saveDeactivation({
      ...basis,
      deactivatedAt: basis.deactivatedAt!,
      deactivationReason: basis.deactivationReason ?? '',
      deactivatedBy: basis.deactivatedBy ?? '',
    });
  }

  // ---- messaging (delegated to ResidentMessaging) -------------------------

  /** Send a non-OTP notification (USSD status replies). */
  async notify(residentId: string, body: string): Promise<boolean> {
    return this.msg.notify(residentId, body);
  }

  messagingConfigured(): boolean {
    return this.msg.messagingConfigured();
  }

  /** Which contact-storage policy this deployment runs, so enrolment keeps the right fields. */
  contactDirectoryMode(): 'none' | 'encrypted' | 'external' {
    return this.msg.contactDirectoryMode();
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

  /**
   * Where the SUSPENSION list is published (ORCS §10).
   *
   * A separate URL from the revocation list, because they are separate credentials with
   * separate `statusPurpose` values. A verifier that fetched one and read it as the other
   * would treat a suspended credential as revoked, or worse, the reverse.
   */
  suspensionListUrl(cfg: CountryConfig): string {
    return `${this.publicBaseUrl()}/.well-known/status/${cfg.countryCode.toLowerCase()}-suspension.json`;
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
  /** The configured biometric authority for the AAL3 step-up, or null when none is set. */
  getBiometricMatcher(): BiometricMatcher | null {
    return this.biometric;
  }
  getLdpIssuer(): LdpIssuer {
    return this.ldpIssuer;
  }
  getStatusListPublisher(): StatusListPublisher {
    return this.statusListPublisher;
  }
  getVerifier(): VcVerifier {
    return this.verifier;
  }
  getStore(): PrismaResidencyStore {
    return this.store;
  }
  /** The ORCS §8 Assurance Registry every assurance value resolves against. */
  getAssuranceRegistry(): AssuranceRegistry {
    return this.assurance;
  }
  /** Persistence for the OIDC provider's own sessions, codes and tokens. */
  getOidcStore(): PrismaOidcStore {
    return this.oidcStore;
  }
  /** Refused applications, so an applicant can be told why and where to appeal. */
  getRefusalStore(): PrismaRefusalStore {
    return this.refusalStore;
  }
  getAudit(): AuditLog {
    return this.audit;
  }
  getConsent(): ConsentService {
    return this.consent;
  }
  /** Release the HSM session, if the signing backend holds one. */
  async onModuleDestroy(): Promise<void> {
    this.jobs?.stop();
    await this.custody.close();
  }

  /** The credential signing key. Custody lives in KeyCustody; this only hands it out. */
  getIssuerKey(): IssuerKey {
    return this.custody.getIssuerKey();
  }

  /** Every public key this deployment has signed with: active first, then retired. */
  issuerPublicJwks(): JWK[] {
    return this.custody.issuerPublicJwks();
  }

  /** The private JWK the OIDC provider signs id_tokens with. See KeyCustody for why it is
   * a separate key from the credential issuer's. */
  async oidcSigningJwk(): Promise<JWK> {
    return this.custody.oidcSigningJwk();
  }


  /**
   * Build the upstream OIDC client, or refuse to boot if the config cannot work.
   *
   * The private key is read HERE rather than at first use, so a deployment that names a
   * missing environment variable fails at startup with the variable's name -- not months
   * later, in front of the first resident who tries to sign in. That is the same posture
   * the issuer key and the foundational `mtls` mode already take: a declared capability
   * that cannot function is a configuration error, not a runtime surprise.
   */
  private buildUpstreamOidc(cfg?: CountryConfig): UpstreamOidcClient | undefined {
    const profile = cfg?.upstreamOidc as UpstreamOidcConfig | undefined;
    if (!profile) return undefined;

    assertUpstreamOidcUsable(profile);

    // The client constructor enforces the rest (at least one acr mapping, at least one
    // pinned key) and throws with its own reasons.
    const client = new UpstreamOidcClient(profile, this.upstreamAuthStore, this.pepper);
    this.log.log(`Upstream OIDC: residents may sign in at ${profile.issuer}`);
    return client;
  }

  /** The external-OP client, when the deployment declares one. */
  getUpstreamOidc(): UpstreamOidcClient | undefined {
    return this.upstreamOidc;
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

  /**
   * Pull each federated peer's published status list into the verifier's cache.
   *
   * Peer revocation is only checkable against a synced snapshot; until one exists, a peer's
   * credential is accepted unchecked on the offline path and rejected outright on the
   * OpenID4VP path. Both are wrong, and both are fixed by having the list.
   *
   * Non-fatal by construction. A peer being unreachable is an ordinary operating condition
   * -- another government's server is not ours to depend on at boot -- and must not stop this
   * deployment starting. An unsynced peer keeps the safe posture: presentations fail closed.
   */
  async syncFederatedStatusLists(): Promise<void> {
    if (!this.federatedPeers.length) return;
    const results = await syncFederatedStatusLists(this.trust, this.federatedPeers, (url) =>
      axios.get(url, { timeout: 10_000 }).then((r) => r.data),
    );
    for (const r of results) {
      const who = r.name ?? r.did;
      if (r.status === 'synced') {
        this.log.log(`Federation: synced status list for ${who}`);
      } else if (r.status === 'not-configured') {
        this.log.warn(
          `Federation: ${who} declares no statusListUrl, so revocation of its credentials ` +
            'cannot be checked here. Presentations of its credentials will be refused as ' +
            'REVOCATION_UNCHECKABLE.',
        );
      } else {
        this.log.warn(
          `Federation: status list for ${who} is ${r.status}${r.detail ? ` (${r.detail})` : ''}. ` +
            'Its credentials will be refused on the presentation path until a sync succeeds.',
        );
      }
    }
  }
}
