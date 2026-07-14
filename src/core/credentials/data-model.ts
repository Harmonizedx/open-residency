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
export function validateCredentialShape(credential: Record<string, unknown>): string[] {
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
  } else if (!Array.isArray(subject) && Object.keys(subject).length === 0) {
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

  // credentialStatus: OPTIONAL, but if present MUST carry a type.
  const status = credential.credentialStatus;
  if (status != null) {
    for (const entry of Array.isArray(status) ? status : [status]) {
      if (!entry || typeof entry !== 'object') {
        errors.push('credentialStatus must be an object');
      } else if (!(entry as Record<string, unknown>).type) {
        errors.push('credentialStatus must have a type');
      }
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
