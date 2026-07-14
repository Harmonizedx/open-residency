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

const CONTEXT_FILES: Record<string, string> = {
  [CREDENTIALS_V2_CONTEXT_URL]: 'credentials-v2.jsonld',
  [RESIDENCY_V1_CONTEXT_URL]: 'residency-v1.jsonld',
};

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
  const document = contexts[url];
  if (!document) {
    throw new Error(
      `refusing to fetch remote JSON-LD context '${url}': pin it under contexts/ and ` +
        `register it in CONTEXT_FILES so that signing and offline verification stay deterministic`,
    );
  }
  return { contextUrl: null, document, documentUrl: url };
};