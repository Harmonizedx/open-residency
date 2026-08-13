// SPDX-License-Identifier: Apache-2.0
import {
  createHash,
  constants as cryptoConstants,
  verify as cryptoVerify,
  KeyObject,
} from 'node:crypto';
import * as jsonld from 'jsonld';
import { base58btcDecode } from './base58';
import { staticDocumentLoader, SECURITY_V2_CONTEXT_URL } from './jsonld/document-loader';

/**
 * Verification of the linked-data proof suites this deployment ACCEPTS but never emits.
 *
 * We issue exactly one proof type -- `DataIntegrityProof` with `eddsa-rdfc-2022` -- and
 * that is not changing: it is the current W3C suite, it is Ed25519, and every key this
 * system holds is Ed25519. But an incoming credential is not ours to choose the format of.
 * A credential issued by a MOSIP/Inji Certify deployment, or by a peer running an older
 * stack, arrives as VC 1.1 carrying `Ed25519Signature2020`, `Ed25519Signature2018` or
 * `RsaSignature2018`, and refusing to verify it is refusing the credential.
 *
 * Three properties are deliberate:
 *
 *   1. VERIFY ONLY. There is no signing path here. Accepting a legacy suite is a
 *      compatibility obligation to issuers we do not control; emitting one would be a
 *      choice, and the choice is no. Nothing in this file can produce a proof.
 *
 *   2. OPT-IN PER PEER. The accepted set is passed in, and the default is the modern suite
 *      alone. A deployment that never talks to an outside issuer never widens its own
 *      attack surface, and one that does widens it for the peer that needs it and no other.
 *
 *   3. FAIL CLOSED. Every failure -- unpinned context, malformed proof, wrong key type,
 *      an algorithm we will not accept -- returns a reason. Nothing throws out of `verify`,
 *      because a thrown error at a call site expecting a boolean is a verification that
 *      might get treated as a pass.
 *
 * All four suites share one signing input, which is what makes them one file:
 *
 *     sha256( canonical proof options ) || sha256( canonical document )
 *
 * They differ only in how that input is signed and where the signature is parked -- a raw
 * multibase `proofValue` for the 2020 suites, a detached JWS in `jws` for the 2018 ones.
 */

/** The suite we issue. Always accepted; it is what our own credentials carry. */
export const MODERN_SUITE = 'eddsa-rdfc-2022';

/** Suites we can verify but will never produce. */
export const LEGACY_SUITES = [
  'Ed25519Signature2020',
  'Ed25519Signature2018',
  'RsaSignature2018',
] as const;

export type LegacyLdSuite = (typeof LEGACY_SUITES)[number];
export type AcceptedLdSuite = typeof MODERN_SUITE | LegacyLdSuite;

export function isLegacyLdSuite(value: string): value is LegacyLdSuite {
  return (LEGACY_SUITES as readonly string[]).includes(value);
}

export interface LdProofLike {
  type?: string;
  cryptosuite?: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  jws?: string;
}

export type LdDocument = Record<string, unknown> & { proof?: LdProofLike | LdProofLike[] };

export interface LdVerificationResult {
  valid: boolean;
  /** Which suite was actually verified, for the audit trail. */
  suite?: AcceptedLdSuite;
  reason?: string;
}

const sha256 = (input: string): Buffer => createHash('sha256').update(input, 'utf8').digest();

async function canonicalize(doc: unknown): Promise<string> {
  return (await (jsonld as any).canonize(doc, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader: staticDocumentLoader,
    // Same reasoning as the issuer: without safe mode an undefined term is silently
    // dropped from the canonical form, so the signature stops covering a claim the
    // document still appears to make.
    safe: true,
  })) as string;
}

/**
 * The proof options, as the signature actually covered them.
 *
 * The signature value itself is removed -- it cannot be an input to its own computation --
 * along with `id`, which every implementation of these suites excludes. `@context` is taken
 * from the enclosing document because the proof is canonicalized as a standalone graph and
 * would otherwise have no context in which to resolve its own terms.
 */
function proofOptions(proof: LdProofLike, context: unknown): Record<string, unknown> {
  const options: Record<string, unknown> = { ...proof };
  delete options.proofValue;
  delete options.jws;
  delete options.signatureValue;
  delete options.id;
  return { '@context': context, ...options };
}

/**
 * The signing inputs to try, in order.
 *
 * There are two because implementations disagree about which context the proof options are
 * canonicalized under, and the disagreement is not resolvable by reading the specs:
 * jsonld-signatures 11.x uses the enclosing document's `@context`, while its 5.x line --
 * which is what most RsaSignature2018 issuers in the field were built on -- hardcodes
 * `https://w3id.org/security/v2`. The same credential therefore has two legitimate
 * canonical forms depending on who signed it, and only the issuer knows which.
 *
 * Trying both is not a weakening. Each candidate is a fully specified encoding, the
 * signature must verify over one of them against a key we already trust, and neither is
 * attacker-chosen: a forger who could produce a valid signature over either form could
 * produce one over the other. The cost is a second canonicalization on the less common
 * path, paid only when the first does not verify.
 */
async function signingInputs(document: LdDocument, proof: LdProofLike): Promise<Buffer[]> {
  const { proof: _drop, ...withoutProof } = document;
  // Computed once: the document half of the input does not vary between candidates. A
  // failure here IS fatal and propagates -- it means the credential's own contexts are not
  // pinned, so there is no canonical form of it at all.
  const documentHash = sha256(await canonicalize(withoutProof));

  const contexts = [document['@context'], SECURITY_V2_CONTEXT_URL];
  const inputs: Buffer[] = [];
  const failures: string[] = [];
  for (const context of contexts) {
    try {
      // Options first. Reversing these produces a value that hashes fine and verifies nowhere.
      inputs.push(
        Buffer.concat([sha256(await canonicalize(proofOptions(proof, context))), documentHash]),
      );
    } catch (e) {
      // A candidate context that cannot express this proof's terms is simply not the one
      // the issuer used -- security/v2 has no definition for Ed25519Signature2020, for
      // instance, and safe mode rightly refuses to drop the term silently. Skipping it is
      // not leniency: the remaining candidates are still fully specified, and if none
      // survives we fail below rather than verifying against nothing.
      failures.push((e as Error).message);
    }
  }
  if (!inputs.length) {
    throw new Error(`no canonical form for this proof (${failures.join('; ')})`);
  }
  return inputs;
}

/**
 * Verify a detached JWS over `payload`, as the 2018-era suites use.
 *
 * The header must carry `b64: false` with `b64` listed in `crit` (RFC 7797): that is what
 * says the payload is the raw bytes rather than a base64url string, and a verifier that
 * ignores it would be checking a signature over different bytes than the signer signed.
 * An unrecognized `crit` entry is a hard failure, which is what `crit` is for.
 */
function verifyDetachedJws(
  jws: string,
  payloads: Buffer[],
  keys: KeyObject[],
  allowedAlgs: readonly string[],
): { ok: boolean; reason?: string } {
  const parts = jws.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'MALFORMED_JWS' };
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (encodedPayload !== '') return { ok: false, reason: 'JWS_PAYLOAD_NOT_DETACHED' };

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'MALFORMED_JWS_HEADER' };
  }

  if (header.b64 !== false) return { ok: false, reason: 'JWS_B64_NOT_FALSE' };
  const crit = header.crit;
  if (!Array.isArray(crit) || !crit.includes('b64')) {
    return { ok: false, reason: 'JWS_B64_NOT_CRITICAL' };
  }
  const unsupportedCrit = crit.filter((c) => c !== 'b64');
  if (unsupportedCrit.length) return { ok: false, reason: 'JWS_UNSUPPORTED_CRIT' };

  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!allowedAlgs.includes(alg)) return { ok: false, reason: `JWS_ALG_NOT_ACCEPTED:${alg}` };

  let signature: Buffer;
  try {
    signature = Buffer.from(encodedSignature, 'base64url');
  } catch {
    return { ok: false, reason: 'MALFORMED_JWS_SIGNATURE' };
  }

  for (const payload of payloads) {
    // RFC 7797 signing input: the encoded header, a dot, then the payload bytes unencoded.
    const input = Buffer.concat([Buffer.from(`${encodedHeader}.`, 'utf8'), payload]);
    for (const key of keys) {
      try {
        const verified =
          alg === 'EdDSA'
            ? cryptoVerify(null, input, key, signature)
            : alg === 'PS256'
              ? cryptoVerify(
                  'sha256',
                  input,
                  {
                    key,
                    padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
                    saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
                  },
                  signature,
                )
              : cryptoVerify('sha256', input, key, signature);
        if (verified) return { ok: true };
      } catch {
        // Wrong key type for this algorithm, or a malformed key in the trust list. Try the
        // next one: one bad entry must not sink the good keys beside it.
        continue;
      }
    }
  }
  return { ok: false, reason: 'BAD_SIGNATURE' };
}

/**
 * RsaSignature2018 accepts both PS256 and RS256.
 *
 * The suite's own specification says RS256, but the reference implementation that most
 * issuers were built on (jsonld-signatures, through its 5.x line) emits PS256 -- and the
 * credentials in the field carry whatever their issuer's library produced. Accepting only
 * one of the two rejects real credentials on a technicality about which nobody agrees.
 * Both are RSA over SHA-256 with the same key; the difference is the padding scheme, and
 * the header states which, so there is no ambiguity to resolve at verification time.
 */
const RSA_2018_ALGS = ['PS256', 'RS256'] as const;
const ED_2018_ALGS = ['EdDSA'] as const;

/**
 * Verify a credential's linked-data proof against a set of the issuer's public keys.
 *
 * A key SET, not a key: an outside issuer rotates on its own schedule, and a credential
 * signed before a rotation has to keep verifying after it.
 */
export async function verifyLdProof(
  credential: LdDocument,
  issuerPublicKeys: KeyObject | KeyObject[],
  accepted: readonly AcceptedLdSuite[] = [MODERN_SUITE],
): Promise<LdVerificationResult> {
  const keys = Array.isArray(issuerPublicKeys) ? issuerPublicKeys : [issuerPublicKeys];
  if (!keys.length) return { valid: false, reason: 'NO_KEYS' };

  const rawProof = credential.proof;
  if (!rawProof) return { valid: false, reason: 'NO_PROOF' };
  // A proof set/chain would need every member checked and a policy for what "enough" means.
  // Until there is a reason to have one, one proof is the only shape we claim to verify.
  if (Array.isArray(rawProof)) return { valid: false, reason: 'PROOF_SET_UNSUPPORTED' };
  const proof = rawProof;

  const suite: AcceptedLdSuite | undefined =
    proof.type === 'DataIntegrityProof'
      ? proof.cryptosuite === MODERN_SUITE
        ? MODERN_SUITE
        : undefined
      : typeof proof.type === 'string' && isLegacyLdSuite(proof.type)
        ? proof.type
        : undefined;

  if (!suite) {
    return {
      valid: false,
      reason: `UNSUPPORTED_SUITE:${proof.type ?? 'none'}${proof.cryptosuite ? `/${proof.cryptosuite}` : ''}`,
    };
  }
  if (!accepted.includes(suite)) return { valid: false, reason: `SUITE_NOT_ACCEPTED:${suite}` };

  // An assertion proof is the only purpose that makes a credential's claims believable.
  // An authentication proof over the same bytes is a different statement, and treating one
  // as the other is how a proof made for one purpose gets replayed into another.
  if (proof.proofPurpose !== 'assertionMethod') {
    return { valid: false, reason: `WRONG_PROOF_PURPOSE:${proof.proofPurpose ?? 'none'}` };
  }

  let payloads: Buffer[];
  try {
    payloads = await signingInputs(credential, proof);
  } catch (e) {
    // Overwhelmingly this is an unpinned context. Say so: the fix is a config change, and
    // a bare "invalid" would send whoever debugs it to the signature instead.
    return { valid: false, reason: `CANONICALIZATION_FAILED:${(e as Error).message}` };
  }

  if (suite === MODERN_SUITE || suite === 'Ed25519Signature2020') {
    const proofValue = proof.proofValue;
    if (typeof proofValue !== 'string' || !proofValue.length) {
      return { valid: false, suite, reason: 'NO_PROOF_VALUE' };
    }
    if (!proofValue.startsWith('z')) {
      // Both suites specify base58btc, whose multibase prefix is 'z'. Another prefix is a
      // different encoding, not a variant to guess at.
      return { valid: false, suite, reason: 'PROOF_VALUE_NOT_BASE58BTC' };
    }
    let signature: Uint8Array;
    try {
      signature = base58btcDecode(proofValue);
    } catch {
      return { valid: false, suite, reason: 'MALFORMED_PROOF_VALUE' };
    }
    for (const payload of payloads) {
      for (const key of keys) {
        try {
          if (cryptoVerify(null, payload, key, signature)) return { valid: true, suite };
        } catch {
          continue;
        }
      }
    }
    return { valid: false, suite, reason: 'BAD_SIGNATURE' };
  }

  const jws = proof.jws;
  if (typeof jws !== 'string' || !jws.length) {
    return { valid: false, suite, reason: 'NO_JWS' };
  }
  const algs = suite === 'RsaSignature2018' ? RSA_2018_ALGS : ED_2018_ALGS;
  const result = verifyDetachedJws(jws, payloads, keys, algs);
  return result.ok ? { valid: true, suite } : { valid: false, suite, reason: result.reason };
}