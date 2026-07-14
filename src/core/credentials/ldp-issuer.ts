import { createHash, sign as cryptoSign, verify as cryptoVerify, KeyObject } from 'node:crypto';
import * as jsonld from 'jsonld';
import { JWK } from 'jose';
import { IssuerKey } from './keystore';
import { base58btc, base58btcDecode } from './base58';
import { ed25519Multikey } from './did';
import {
  CREDENTIALS_V2_CONTEXT_URL,
  RESIDENCY_V1_CONTEXT_URL,
  staticDocumentLoader,
} from './jsonld/document-loader';

/**
 * Data Integrity issuance with the `eddsa-rdfc-2022` cryptosuite.
 *
 * Why this exists alongside the VC-JWT issuer: the MOSIP Inji wallet — and the
 * OpenWallet stack generally — will not accept `jwt_vc_json`. Its supported-format
 * list is `ldp_vc` / `mso_mdoc` / SD-JWT. So a residency credential that a real wallet
 * can actually hold has to be a JSON-LD credential with a Data Integrity proof.
 *
 * We keep VC-JWT too. It stays the right format for the offline path: it is compact
 * enough to fit in a printed QR code and needs no canonicalization to verify. The two
 * formats carry identical claims and share one status-list entry, so revoking a
 * resident revokes both.
 *
 * Signing follows the VC-DI-EDDSA spec:
 *   1. canonicalize the proof options   -> sha256 -> proofConfigHash
 *   2. canonicalize the credential      -> sha256 -> documentHash
 *   3. sign  ( proofConfigHash || documentHash )  with Ed25519
 * The proof options hash goes FIRST; getting that order wrong produces a proof that
 * looks fine and verifies nowhere.
 */

const CRYPTOSUITE = 'eddsa-rdfc-2022';

export interface LdpProof {
  type: 'DataIntegrityProof';
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

export type LdpCredential = Record<string, unknown> & { proof?: LdpProof };

async function canonicalize(doc: unknown): Promise<string> {
  return (await (jsonld as any).canonize(doc, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader: staticDocumentLoader,
    // Safe mode turns "this term is not in any @context" from a silent drop into a
    // thrown error. Without it, a claim we forgot to define would simply vanish from
    // the canonical form and therefore from what the signature covers -- the document
    // would still verify while no longer attesting the claim. That is a forgery vector,
    // not a formatting nit.
    safe: true,
  })) as string;
}

const sha256 = (input: string): Buffer => createHash('sha256').update(input, 'utf8').digest();

/** Build the hash that Ed25519 actually signs, per VC-DI-EDDSA. */
async function hashData(
  document: Record<string, unknown>,
  proofConfig: Record<string, unknown>,
): Promise<Buffer> {
  const proofConfigHash = sha256(await canonicalize(proofConfig));
  const documentHash = sha256(await canonicalize(document));
  return Buffer.concat([proofConfigHash, documentHash]);
}

/** The verification method id for a Multikey, which is what this cryptosuite resolves. */
export function multikeyVerificationMethod(issuerDid: string, publicJwk: JWK): string {
  return `${issuerDid}#${ed25519Multikey(publicJwk)}`;
}

export class LdpIssuer {
  constructor(private key: IssuerKey) {}

  /** Attach a DataIntegrityProof to an unsigned JSON-LD credential. */
  async sign(unsigned: Record<string, unknown>, issuerDid: string): Promise<LdpCredential> {
    const { proof: _discard, ...document } = unsigned as LdpCredential;

    const proofConfig: Record<string, unknown> = {
      // The proof options are canonicalized on their own, so they need the document's
      // context to resolve their own terms.
      '@context': document['@context'],
      type: 'DataIntegrityProof',
      cryptosuite: CRYPTOSUITE,
      created: new Date().toISOString(),
      verificationMethod: multikeyVerificationMethod(issuerDid, this.key.publicJwk),
      proofPurpose: 'assertionMethod',
    };

    const toSign = await hashData(document, proofConfig);
    const signature = cryptoSign(null, toSign, this.key.privateKey as unknown as KeyObject);

    const { '@context': _ctx, ...proofWithoutContext } = proofConfig;
    return {
      ...document,
      proof: {
        ...(proofWithoutContext as Omit<LdpProof, 'proofValue'>),
        proofValue: base58btc(new Uint8Array(signature)),
      },
    } as LdpCredential;
  }

  /** Verify a DataIntegrityProof against a known issuer public key. */
  static async verify(credential: LdpCredential, issuerPublicKey: KeyObject): Promise<boolean> {
    const { proof, ...document } = credential;
    if (!proof || proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== CRYPTOSUITE) {
      return false;
    }

    const { proofValue, ...proofOptions } = proof;
    const proofConfig: Record<string, unknown> = {
      '@context': (document as Record<string, unknown>)['@context'],
      ...proofOptions,
    };

    let signed: Buffer;
    try {
      signed = await hashData(document as Record<string, unknown>, proofConfig);
    } catch {
      return false;
    }

    let signature: Uint8Array;
    try {
      signature = base58btcDecode(proofValue);
    } catch {
      return false;
    }

    return cryptoVerify(null, signed, issuerPublicKey, signature);
  }
}

/** The `@context` every residency credential we issue in JSON-LD form declares. */
export const RESIDENCY_LDP_CONTEXT = [CREDENTIALS_V2_CONTEXT_URL, RESIDENCY_V1_CONTEXT_URL];