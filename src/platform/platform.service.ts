import { Injectable, Logger } from '@nestjs/common';
import { join } from 'node:path';
import { JWK } from 'jose';
import { CountryConfig, loadCountryConfigs } from '../core/config/country-config';
import { ProviderRegistry } from '../core/foundational/registry';
import { KeyStore, IssuerKey } from '../core/credentials/keystore';
import { VcIssuer } from '../core/credentials/vc-issuer';
import { LdpIssuer } from '../core/credentials/ldp-issuer';
import { residencyContextDocument } from '../core/credentials/jsonld/document-loader';
import { VcVerifier, TrustedIssuer } from '../core/credentials/vc-verifier';
import { buildDidWebDocument } from '../core/credentials/did';
import { ResidencyService } from '../core/residency/residency-service';
import { Oid4vciService } from '../core/oid4vci/oid4vci-service';
import { Oid4vpService } from '../core/oid4vp/oid4vp-service';
import { OtpService, LoggingOtpSender } from '../core/sso/otp';
import { SsoAuthService } from '../core/sso/sso-auth';
import { VpVerifier, VpTrustedIssuer, keyObjectFromJwk } from '../core/oid4vp/vp-verifier';
import { AuditLog } from '../core/audit/audit-log';
import { ConsentService } from '../core/consent/consent';
import {
  PrismaAuditStore,
  PrismaConsentStore,
  PrismaOid4vciStore,
  PrismaOid4vpStore,
  PrismaOtpStore,
  PrismaResidencyStore,
} from '../prisma/prisma.service';

/**
 * Central wiring for the framework-agnostic core. Holds the loaded country configs,
 * the issuer key, the issuer/verifier, and the residency orchestration, and exposes
 * them to the thin Nest controllers.
 */
@Injectable()
export class PlatformService {
  private readonly log = new Logger('Platform');
  private configs!: Map<string, CountryConfig>;
  private key!: IssuerKey;
  private registry!: ProviderRegistry;
  private issuer!: VcIssuer;
  private ldpIssuer!: LdpIssuer;
  private verifier!: VcVerifier;
  private residency!: ResidencyService;
  private oid4vci!: Oid4vciService;
  private oid4vp!: Oid4vpService;
  private vpVerifier!: VpVerifier;
  private ssoAuth!: SsoAuthService;
  private audit!: AuditLog;
  private consent!: ConsentService;
  private platformIssuerDid!: string;
  private trust = new Map<string, TrustedIssuer>();

  constructor(
    private store: PrismaResidencyStore,
    private auditStore: PrismaAuditStore,
    private consentStore: PrismaConsentStore,
    private oid4vciStore: PrismaOid4vciStore,
    private oid4vpStore: PrismaOid4vpStore,
    private otpStore: PrismaOtpStore,
  ) {}

  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    const dir = process.env.COUNTRY_CONFIG_DIR ?? join(process.cwd(), 'config/countries');
    this.configs = loadCountryConfigs(dir);
    this.log.log(`Loaded ${this.configs.size} country config(s): ${[...this.configs.keys()].join(', ')}`);

    // Issuer key: from env JWK in production (KMS-exported / sealed), generated in dev.
    const jwkEnv = process.env.ISSUER_PRIVATE_JWK;
    if (jwkEnv) {
      const jwk = JSON.parse(jwkEnv) as JWK;
      this.key = await KeyStore.fromJwk(jwk, process.env.ISSUER_KID ?? 'issuer-key-1');
    } else {
      this.key = await KeyStore.generate(process.env.ISSUER_KID ?? 'issuer-key-1');
      this.log.warn('No ISSUER_PRIVATE_JWK set: generated an ephemeral dev key. Do NOT use in production.');
    }

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
        publicJwk: this.key.publicJwk,
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
        publicKeyObject: keyObjectFromJwk(this.key.publicJwk),
      });
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
    // code as the fallback. The OTP sender is a dev stub that logs the code; a production
    // deployment replaces it with one backed by its own SMS gateway and contact directory,
    // which is what keeps plaintext phone numbers out of our store.
    const otp = new OtpService(this.otpStore, new LoggingOtpSender(), () => crypto.randomUUID());
    this.ssoAuth = new SsoAuthService(this.oid4vp, otp, this.store);

    // Audit and consent frameworks.
    this.platformIssuerDid =
      process.env.PLATFORM_ISSUER_DID ??
      this.listConfigs()[0]?.credential.issuerDid ??
      'did:web:openresidency.example';
    this.audit = new AuditLog(this.auditStore);
    this.consent = new ConsentService(this.consentStore, this.key, this.platformIssuerDid);
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
  getIssuerKey(): IssuerKey {
    return this.key;
  }

  didDocument(countryCode: string): Record<string, unknown> | undefined {
    const cfg = this.getConfig(countryCode);
    if (!cfg) return undefined;
    return buildDidWebDocument(cfg.credential.issuerDid, this.key.publicJwk);
  }

  /** Refresh the verifier's cached status list for a country from the store. */
  async syncStatusList(cfg: CountryConfig): Promise<void> {
    const list = await this.store.loadStatusList(cfg.countryCode);
    const t = this.trust.get(cfg.credential.issuerDid);
    if (t) t.statusLists = { [this.statusListUrl(cfg)]: list };
  }
}
