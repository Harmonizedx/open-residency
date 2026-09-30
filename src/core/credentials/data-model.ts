// SPDX-License-Identifier: Apache-2.0
/**
 * The normative requirements of the W3C Verifiable Credentials Data Model 2.0.
 *
 * These are conformance rules, not house style. Each one corresponds to a MUST in the
 * specification, and the official test suite probes each by sending a credential that
 * violates it and expecting a rejection -- so anything not enforced here is a test we
 * fail there, and a claim in our README that is not true.
 *
 * Spec: https://www.w3.org/TR/vc-data-model-2.0/
 */
import { createHash } from 'node:crypto';
import { base58btcDecode } from './base58';

export const CREDENTIALS_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

export function typesOf(doc: Record<string, unknown> | string): string[] {
  if (typeof doc === 'string') return [];
  const t = doc.type;
  return Array.isArray(t) ? t.map(String) : t ? [String(t)] : [];
}

export function issuerIdOf(credential: Record<string, unknown>): string | undefined {
  const issuer = credential.issuer;
  if (typeof issuer === 'string') return issuer;
  if (issuer && typeof issuer === 'object') {
    const id = (issuer as { id?: unknown }).id;
    if (typeof id === 'string') return id;
  }
  return undefined;
}

/** A DID and a URN are both URIs, and neither parses with `new URL()`. */
export function isUri(value: string): boolean {
  if (/^did:[a-z0-9]+:.+/i.test(value)) return true;
  if (/^urn:[a-z0-9][a-z0-9-]{0,31}:.+/i.test(value)) return true;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * An XMLSchema `dateTimeStamp`, which -- unlike `dateTime` -- REQUIRES a timezone offset.
 * `2026-07-14T10:00:00` is a valid dateTime and an invalid dateTimeStamp, and the
 * distinction matters: a credential whose validity window has no timezone means different
 * things in Lagos and in Delhi.
 */
export function isDateTimeStamp(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value)) return false;
  return !Number.isNaN(new Date(value).getTime());
}

/** Validate a credential against the VC Data Model 2.0. Returns the list of violations. */
export function validateCredentialShape(
  credential: Record<string, unknown>,
  options: CredentialShapeOptions = {},
): string[] {
  const errors: string[] = [];

  // @context: REQUIRED, and the FIRST value must be the VC v2 context. Ordering is
  // normative, not cosmetic -- a later context could otherwise redefine the core terms.
  const context = credential['@context'];
  if (!Array.isArray(context) || context.length === 0) {
    errors.push('@context is required and must be an array');
  } else if (context[0] !== CREDENTIALS_V2_CONTEXT) {
    errors.push(`the first @context value must be ${CREDENTIALS_V2_CONTEXT}`);
  }

  // type: REQUIRED, MUST include VerifiableCredential.
  const types = typesOf(credential);
  if (types.length === 0) {
    errors.push('type is required');
  } else if (!types.includes('VerifiableCredential')) {
    errors.push('type must include VerifiableCredential');
  }

  // credentialSubject: REQUIRED and non-empty. A credential asserting nothing about
  // anybody is not a credential.
  const subject = credential.credentialSubject;
  if (!subject || typeof subject !== 'object') {
    errors.push('credentialSubject is required');
  } else if (Array.isArray(subject)) {
    // A set of subjects, where EACH is the subject of one or more claims. One empty
    // member is as meaningless as a single empty subject -- and harder to spot, which is
    // precisely why it needs checking rather than being waved through with the set.
    if (subject.length === 0) {
      errors.push('credentialSubject must not be empty');
    } else if (
      subject.some((s) => !s || typeof s !== 'object' || Object.keys(s).length === 0)
    ) {
      errors.push('every credentialSubject must be a non-empty object');
    }
  } else if (Object.keys(subject).length === 0) {
    errors.push('credentialSubject must not be empty');
  }

  // issuer: REQUIRED; a URI, or an object carrying one as `id`.
  const issuerId = issuerIdOf(credential);
  if (credential.issuer == null) {
    errors.push('issuer is required');
  } else if (!issuerId) {
    errors.push('issuer must be a URI or an object with an id');
  } else if (!isUri(issuerId)) {
    errors.push('issuer id must be a URI');
  }

  // id: OPTIONAL, but if present MUST be a single URI.
  if (credential.id != null) {
    if (Array.isArray(credential.id)) errors.push('id must not be an array');
    else if (typeof credential.id !== 'string' || !isUri(credential.id)) {
      errors.push('id must be a URI');
    }
  }

  // validFrom / validUntil: OPTIONAL, but if present MUST be dateTimeStamps.
  for (const field of ['validFrom', 'validUntil'] as const) {
    const value = credential[field];
    if (value != null && !isDateTimeStamp(value)) {
      errors.push(`${field} must be an XMLSchema dateTimeStamp`);
    }
  }

  // These properties are all OPTIONAL, but each entry MUST carry a `type`. Without one a
  // consumer cannot tell what the object is meant to be, so it cannot act on it -- an
  // untyped `refreshService` is an endpoint of unknown protocol, and an untyped
  // `termsOfUse` is a policy nobody can evaluate.
  for (const field of TYPED_ENTRY_PROPERTIES) {
    errors.push(...typedEntryErrors(credential[field], field));
  }

  // credentialSchema additionally REQUIRES an `id` that is a URL identifying the schema.
  for (const entry of entriesOf(credential.credentialSchema)) {
    if (!entry || typeof entry !== 'object') continue;
    const id = (entry as Record<string, unknown>).id;
    if (typeof id !== 'string' || !isUri(id)) {
      errors.push('credentialSchema must have an id that is a URL');
    }
  }

  errors.push(...relatedResourceErrors(credential.relatedResource, options));

  return errors;
}

/** Properties whose every entry MUST specify a `type`, per VC Data Model 2.0. */
const TYPED_ENTRY_PROPERTIES = [
  'credentialStatus',
  'credentialSchema',
  'termsOfUse',
  'evidence',
  'refreshService',
  'proof',
] as const;

/** Normalize a "one or more" property into a list. Absent yields an empty list. */
function entriesOf(value: unknown): unknown[] {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function typedEntryErrors(value: unknown, field: string): string[] {
  const errors: string[] = [];
  for (const entry of entriesOf(value)) {
    if (!entry || typeof entry !== 'object') {
      errors.push(`${field} must be an object`);
    } else if (!(entry as Record<string, unknown>).type) {
      errors.push(`${field} must have a type`);
    }
  }
  return errors;
}

/** How a caller supplies the bytes behind a `relatedResource` id, if it holds them. */
export interface CredentialShapeOptions {
  /**
   * Return the exact bytes a consumer would retrieve for `url`, or undefined if unknown.
   * Undefined means "cannot check", not "does not match": a resource we do not hold is
   * left unverified rather than rejected, because refusing it would make an unpinned but
   * perfectly valid resource unusable.
   */
  resolveResourceBytes?: (url: string) => Buffer | undefined;
}

/**
 * VCDM 2.0 §5.3, Integrity of Related Resources.
 *
 * Each entry MUST be an object with a unique `id` and at least one digest. Where we can
 * resolve the resource offline, the digest is checked against it -- a stated digest that
 * does not match the thing it names is worse than no digest at all, because it looks like
 * an integrity guarantee while providing none.
 */
function relatedResourceErrors(value: unknown, options: CredentialShapeOptions = {}): string[] {
  const errors: string[] = [];
  const entries = entriesOf(value);
  const seen = new Set<string>();

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push('relatedResource must be one or more objects');
      continue;
    }
    const resource = entry as Record<string, unknown>;

    const id = resource.id;
    if (typeof id !== 'string' || !isUri(id)) {
      errors.push('relatedResource must have an id that is a URI');
    } else if (seen.has(id)) {
      errors.push(`relatedResource id must be unique among the list: '${id}' is repeated`);
    } else {
      seen.add(id);
    }

    const sri = resource.digestSRI;
    const multibase = resource.digestMultibase;
    if (sri == null && multibase == null) {
      errors.push('relatedResource must have at least a digestSRI or a digestMultibase');
      continue;
    }

    const bytes = typeof id === 'string' ? options.resolveResourceBytes?.(id) : undefined;
    if (!bytes) continue;

    if (sri != null && !digestSriMatches(String(sri), bytes)) {
      errors.push(`relatedResource digestSRI does not match the resource at '${String(id)}'`);
    }
    if (multibase != null && !digestMultibaseMatches(String(multibase), bytes)) {
      errors.push(
        `relatedResource digestMultibase does not match the resource at '${String(id)}'`,
      );
    }
  }

  return errors;
}

/** Hash lengths, in bytes, of the SHA-2 functions a digest may use. */
const HASH_BY_LENGTH: Record<number, 'sha256' | 'sha384' | 'sha512'> = {
  32: 'sha256',
  48: 'sha384',
  64: 'sha512',
};

/** Subresource Integrity: `<algorithm>-<base64 digest>`, per the SRI specification. */
function digestSriMatches(sri: string, bytes: Buffer): boolean {
  const match = /^(sha256|sha384|sha512)-(.+)$/.exec(sri.trim());
  if (!match) return false;
  const [, algorithm, encoded] = match;
  let expected: Buffer;
  try {
    expected = Buffer.from(encoded, 'base64');
  } catch {
    return false;
  }
  return createHash(algorithm).update(bytes).digest().equals(expected);
}

/**
 * `digestMultibase`: a multibase-encoded digest. The algorithm is not named, so it is
 * inferred from the digest length -- which is unambiguous across SHA-256/384/512.
 */
function digestMultibaseMatches(multibase: string, bytes: Buffer): boolean {
  const value = multibase.trim();
  let expected: Buffer;
  if (value.startsWith('u')) {
    expected = Buffer.from(value.slice(1), 'base64url');
  } else if (value.startsWith('z')) {
    try {
      expected = Buffer.from(base58btcDecode(value.slice(1)));
    } catch {
      return false;
    }
  } else {
    return false;
  }

  const algorithm = HASH_BY_LENGTH[expected.length];
  if (!algorithm) return false;
  return createHash(algorithm).update(bytes).digest().equals(expected);
}

/**
 * Validate a presentation against the VC Data Model 2.0.
 *
 * A presentation carries the same `@context` requirements as a credential, and they are
 * requirements for the same reason: the context fixes what every term in the document
 * means, so a presentation that omits it -- or lets another context be consulted first --
 * is one whose claims can be reinterpreted after the fact.
 */
export function validatePresentationShape(presentation: Record<string, unknown>): string[] {
  const errors: string[] = [];

  const context = presentation['@context'];
  if (context == null) {
    errors.push('@context is required');
  } else {
    const list = Array.isArray(context) ? context : [context];
    if (list.length === 0) {
      errors.push('@context is required');
    } else if (list[0] !== CREDENTIALS_V2_CONTEXT) {
      errors.push(`the first @context value must be ${CREDENTIALS_V2_CONTEXT}`);
    }
    // Subsequent entries must each be something a JSON-LD processor can treat as a
    // context: a URL, or an inline context object.
    for (const entry of list.slice(1)) {
      if (typeof entry === 'string') {
        if (!isUri(entry)) errors.push(`@context entry '${entry}' is not a URL`);
      } else if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        errors.push('every @context entry must be a URL or a JSON-LD context object');
      }
    }
  }

  if (!typesOf(presentation).includes('VerifiablePresentation')) {
    errors.push('type must include VerifiablePresentation');
  }

  if (presentation.id != null) {
    if (typeof presentation.id !== 'string' || !isUri(presentation.id)) {
      errors.push('id must be a URI');
    }
  }

  return errors;
}

/**
 * Validate a BitstringStatusListEntry, per Bitstring Status List v1.0.
 * https://www.w3.org/TR/vc-bitstring-status-list/
 */
export function validateStatusEntry(entry: Record<string, unknown>): string[] {
  const errors: string[] = [];

  if (entry.type !== 'BitstringStatusListEntry') {
    errors.push("credentialStatus.type must be 'BitstringStatusListEntry'");
  }
  if (typeof entry.statusPurpose !== 'string') {
    errors.push('statusPurpose is required');
  }
  // statusListIndex MUST be a string, not a number. It is an arbitrary-precision integer,
  // and JSON numbers are IEEE-754 doubles -- a large index would silently lose precision.
  if (typeof entry.statusListIndex !== 'string') {
    errors.push('statusListIndex must be a string');
  } else if (!/^\d+$/.test(entry.statusListIndex)) {
    errors.push('statusListIndex must be a non-negative integer');
  }
  if (typeof entry.statusListCredential !== 'string' || !isUri(entry.statusListCredential)) {
    errors.push('statusListCredential must be a URL');
  }

  return errors;
}

/**
 * Validate the published status list credential itself.
 *
 * The `encodedList` check is the one that matters: the spec requires a MULTIBASE-encoded
 * base64url string, which carries a leading 'u'. Bare base64url looks correct to a human
 * and decodes to garbage in a strict verifier, which would take the leading 'H' of the
 * GZIP magic bytes as the multibase identifier.
 */
export function validateStatusListCredential(credential: Record<string, unknown>): string[] {
  const errors = validateCredentialShape(credential);

  if (!typesOf(credential).includes('BitstringStatusListCredential')) {
    errors.push('type must include BitstringStatusListCredential');
  }

  const subject = credential.credentialSubject as Record<string, unknown> | undefined;
  if (!subject) return errors;

  if (subject.type !== 'BitstringStatusList') {
    errors.push("credentialSubject.type must be 'BitstringStatusList'");
  }
  if (typeof subject.statusPurpose !== 'string') {
    errors.push('credentialSubject.statusPurpose is required');
  }

  const encoded = subject.encodedList;
  if (typeof encoded !== 'string') {
    errors.push('encodedList is required');
  } else if (!encoded.startsWith('u')) {
    errors.push("encodedList must be multibase base64url (leading 'u')");
  }

  return errors;
}
