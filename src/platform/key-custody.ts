// SPDX-License-Identifier: Apache-2.0
import { Injectable, Logger } from '@nestjs/common';
import { JWK, exportJWK, generateKeyPair, importJWK } from 'jose';
import { KeyStore, IssuerKey } from '../core/credentials/keystore';
import { Pkcs11Signer } from '../core/credentials/signers/pkcs11-signer';
import { GcpKmsSigner } from '../core/credentials/signers/gcp-kms-signer';
import { AwsKmsSigner } from '../core/credentials/signers/aws-kms-signer';

/**
 * Custody of the signing keys, and nothing else.
 *
 * Lifted out of PlatformService because it is the one concern in there that was wholly
 * self-contained: 268 lines touching no state but its own. Everything else in that class
 * composes the rest of the system; this decides where a private key lives and refuses to
 * start when the answer is unacceptable. Those are different jobs with different reasons to
 * change -- a new KMS backend has nothing to say about how residency is wired -- and they
 * were only in one file because that is where the constructor happened to be.
 *
 * The rules it enforces are unchanged, and they are the load-bearing part: a production
 * deployment may not sign with an ephemeral key, a declared backend that cannot reach its
 * key fails at boot rather than at first issuance, and a retired key is published for
 * verification but never signs.
 */
@Injectable()
export class KeyCustody {
  private readonly log = new Logger('KeyCustody');
  private key!: IssuerKey;
  /** Public halves of keys rotated away from. Verified against, never signed with. */
  private retiredJwks: JWK[] = [];
  /** Set when the signing backend holds an external resource (an HSM session) to release. */
  private closeSigner?: () => Promise<void>;

  /** Resolve the signing key and the retired set. Throws rather than start unsafely. */
  async init(): Promise<void> {
    this.key = await this.loadIssuerKey();
    this.retiredJwks = this.loadRetiredJwks();
  }

  /**
   * Release an external signing backend, if one is held.
   *
   * Separate from the platform's own shutdown so an HSM session is closed by the thing that
   * opened it.
   */
  async close(): Promise<void> {
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
}
