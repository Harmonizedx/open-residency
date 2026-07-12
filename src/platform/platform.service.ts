import { Injectable, Logger } from '@nestjs/common';
import { join } from 'node:path';
import { JWK } from 'jose';
import { CountryConfig, loadCountryConfigs } from '../core/config/country-config';
import { ProviderRegistry } from '../core/foundational/registry';
import { KeyStore, IssuerKey } from '../core/credentials/keystore';
import { VcIssuer } from '../core/credentials/vc-issuer';
import { VcVerifier, TrustedIssuer } from '../core/credentials/vc-verifier';
import { buildDidWebDocument } from '../core/credentials/did';
import { ResidencyService } from '../core/residency/residency-service';
import { AuditLog } from '../core/audit/audit-log';
import { ConsentService } from '../core/consent/consent';
import {
  PrismaAuditStore,
  PrismaConsentStore,
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
  private verifier!: VcVerifier;
  private residency!: ResidencyService;
  private audit!: AuditLog;
  private consent!: ConsentService;
  private platformIssuerDid!: string;
  private trust = new Map<string, TrustedIssuer>();

  constructor(
    private store: PrismaResidencyStore,
    private auditStore: PrismaAuditStore,
    private consentStore: PrismaConsentStore,
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

    const pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper';
    this.registry = new ProviderRegistry(pepper);
    this.issuer = new VcIssuer(this.key);
    this.residency = new ResidencyService(
      this.registry,
      this.issuer,
      this.store,
      (cfg) => this.statusListUrl(cfg),
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

    // Audit and consent frameworks.
    this.platformIssuerDid =
      process.env.PLATFORM_ISSUER_DID ??
      this.listConfigs()[0]?.credential.issuerDid ??
      'did:web:openresidency.example';
    this.audit = new AuditLog(this.auditStore);
    this.consent = new ConsentService(this.consentStore, this.key, this.platformIssuerDid);
  }

  statusListUrl(cfg: CountryConfig): string {
    const base = process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000';
    return `${base}/.well-known/status/${cfg.countryCode.toLowerCase()}.json`;
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
