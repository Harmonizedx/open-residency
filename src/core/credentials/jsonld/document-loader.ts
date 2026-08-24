// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * A static, offline JSON-LD document loader.
 *
 * Canonicalization (URDNA2015) has to dereference every `@context` a credential
 * declares. Doing that over the network would be wrong here for three reasons:
 *
 *   1. Determinism. A signature is computed over the canonical form of the document.
 *      If a context is fetched at signing time and again at verification time, and it
 *      changed in between, the signature silently stops verifying.
 *   2. Availability. A verifier at a rural clinic has no internet. Requiring an HTTP
 *      round-trip to w3.org to check a residency card defeats the purpose.
 *   3. Integrity. A remote context is an input to what the signature covers. Whoever
 *      serves it can influence how claims are interpreted.
 *
 * So every context we use is pinned in `contexts/` and served from our own domain, and
 * this loader refuses to fetch anything it does not already hold.
 */

export const CREDENTIALS_V2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';
export const RESIDENCY_V1_CONTEXT_URL = 'https://openresidency.org/contexts/residency/v1';
/** Used only by the W3C test suite's example credentials, never by one we issue. */
export const CREDENTIALS_EXAMPLES_V2_CONTEXT_URL =
  'https://www.w3.org/ns/credentials/examples/v2';

/**
 * Contexts needed to VERIFY credentials issued by other systems, never to issue one here.
 *
 * A credential from an outside issuer -- a MOSIP/Inji Certify deployment, a peer running
 * an older stack -- is a VC 1.1 document carrying a legacy proof suite, and canonicalizing
 * it requires the contexts that define those terms. Pinning them is what lets that
 * verification happen offline and deterministically, on the same terms as everything else
 * here: `security/v2` pulls in `security/v1`, so both are held.
 */
export const CREDENTIALS_V1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1';
export const SECURITY_V1_CONTEXT_URL = 'https://w3id.org/security/v1';
export const SECURITY_V2_CONTEXT_URL = 'https://w3id.org/security/v2';
export const ED25519_2020_CONTEXT_URL = 'https://w3id.org/security/suites/ed25519-2020/v1';

const CONTEXT_FILES: Record<string, string> = {
  [CREDENTIALS_V2_CONTEXT_URL]: 'credentials-v2.jsonld',
  [RESIDENCY_V1_CONTEXT_URL]: 'residency-v1.jsonld',
  [CREDENTIALS_EXAMPLES_V2_CONTEXT_URL]: 'credentials-examples-v2.jsonld',
  [CREDENTIALS_V1_CONTEXT_URL]: 'credentials-v1.jsonld',
  [SECURITY_V1_CONTEXT_URL]: 'security-v1.jsonld',
  [SECURITY_V2_CONTEXT_URL]: 'security-v2.jsonld',
  [ED25519_2020_CONTEXT_URL]: 'security-ed25519-2020-v1.jsonld',
};

/**
 * Contexts a deployment pins for a specific peer issuer, registered at startup from config.
 *
 * An outside issuer defines its own credential terms in its own context document. We
 * cannot ship those -- there is one per peer, and they are not ours to vendor -- but the
 * loader must still refuse to fetch them, or every reason the loader exists evaporates for
 * exactly the credentials it is least able to vouch for. So a deployer pins the peer's
 * context alongside the peer's keys, and it is held here.
 */
const peerContexts = new Map<string, unknown>();

/**
 * Pin a peer issuer's context document.
 *
 * Refuses to shadow a built-in context. A peer-supplied document that redefined the terms
 * of `credentials/v1` or a signature suite would change what a signature is understood to
 * cover, which is a trust-store poisoning vector rather than a configuration convenience --
 * the same reason `applyFederation` refuses to overwrite an issuer already in the map.
 */
export function registerPeerContext(url: string, document: unknown): void {
  if (CONTEXT_FILES[url]) {
    throw new Error(
      `refusing to override the built-in JSON-LD context '${url}' with a peer-supplied one`,
    );
  }
  const existing = peerContexts.get(url);
  if (existing && JSON.stringify(existing) !== JSON.stringify(document)) {
    throw new Error(
      `peer JSON-LD context '${url}' is already pinned with different content; two peers ` +
        `cannot claim the same context URL`,
    );
  }
  peerContexts.set(url, document);
}

/** Drop all peer-pinned contexts. For tests; a running deployment pins once at startup. */
export function clearPeerContexts(): void {
  peerContexts.clear();
}

function contextsDir(): string {
  return process.env.CONTEXTS_DIR ?? join(process.cwd(), 'contexts');
}

let cache: Record<string, unknown> | undefined;

/** Load and memoize the pinned contexts from disk. */
export function loadContexts(): Record<string, unknown> {
  if (cache) return cache;
  const dir = contextsDir();
  const loaded: Record<string, unknown> = {};
  for (const [url, file] of Object.entries(CONTEXT_FILES)) {
    loaded[url] = JSON.parse(readFileSync(join(dir, file), 'utf8'));
  }
  cache = loaded;
  return loaded;
}

/**
 * The raw, unparsed bytes of a pinned document, or undefined if we do not hold it.
 *
 * `relatedResource` integrity (VCDM 2.0 §5.3) is a digest over the bytes a consumer would
 * retrieve, so it cannot be computed from the parsed object -- reserialising JSON does not
 * reproduce the original whitespace or key order. This reads the pinned file as bytes.
 *
 * Only pinned resources can be checked. Fetching an arbitrary URL to digest it is exactly
 * what `staticDocumentLoader` refuses to do, and for the same reasons; an unpinned resource
 * is therefore left unverified rather than fetched.
 */
export function pinnedResourceBytes(url: string): Buffer | undefined {
  const file = CONTEXT_FILES[url];
  if (!file) return undefined;
  try {
    return readFileSync(join(contextsDir(), file));
  } catch {
    return undefined;
  }
}

/** The context document we publish at RESIDENCY_V1_CONTEXT_URL. */
export function residencyContextDocument(): unknown {
  return loadContexts()[RESIDENCY_V1_CONTEXT_URL];
}

export type DocumentLoader = (
  url: string,
) => Promise<{ contextUrl: null; document: unknown; documentUrl: string }>;

/**
 * The loader handed to jsonld. Anything not pinned is a hard error rather than a
 * network fetch, so an unpinned context fails loudly at issuance instead of producing
 * a credential nobody can verify offline.
 */
export const staticDocumentLoader: DocumentLoader = async (url: string) => {
  const contexts = loadContexts();
  // Built-ins win over peer-pinned entries. registerPeerContext already refuses to shadow
  // one; this is the second lock on the same door, so the ordering cannot be undone by a
  // future change to the registration path alone.
  const document = contexts[url] ?? peerContexts.get(url);
  if (!document) {
    throw new Error(
      `refusing to fetch remote JSON-LD context '${url}': pin it under contexts/ and ` +
        `register it in CONTEXT_FILES so that signing and offline verification stay deterministic` +
        `, or -- for another issuer's own context -- pin it in this deployment's federation config`,
    );
  }
  return { contextUrl: null, document, documentUrl: url };
};