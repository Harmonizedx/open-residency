/**
 * Shared, transport-agnostic mapping from a provider's response *body* to a
 * NormalizedIdentity / FoundationalVerificationResult.
 *
 * The response body is a plain object regardless of how it arrived -- parsed JSON from a
 * REST call, an XML/SOAP document run through parseXml(), or a single record picked out of
 * an imported dataset file. Extracting this here is what lets GENERIC_REST, GENERIC_XML,
 * and DATASET_FILE stay thin and behave identically for attribute mapping, the verified
 * flag, subject tokenization, and applicant-binding semantics.
 */
import {
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  NormalizedIdentity,
  ProviderConfig,
} from './types';
import { ApplicantBinding } from '../proofing/binding';
import { getPath, tokenizeSubject } from './util';

/** Build outbound auth headers from config. Secrets come from env, never from the file. */
export function buildAuthHeaders(cfg: ProviderConfig): Record<string, string> {
  const auth = cfg.auth;
  if (!auth || auth.type === 'none') return {};
  const secret = auth.secretEnv ? process.env[auth.secretEnv] : undefined;
  switch (auth.type) {
    case 'apiKey':
      return { [auth.headerName ?? 'x-api-key']: secret ?? '' };
    case 'bearer':
      return { authorization: `Bearer ${secret ?? ''}` };
    case 'basic': {
      const id = auth.clientIdEnv ? process.env[auth.clientIdEnv] : '';
      const pw = auth.clientSecretEnv ? process.env[auth.clientSecretEnv] : '';
      return { authorization: 'Basic ' + Buffer.from(`${id}:${pw}`).toString('base64') };
    }
    default:
      return {};
  }
}

/**
 * Evaluate the configured success flag against the response body. Strict equality is tried
 * first (preserving JSON semantics: `match === true`); a case-insensitive string comparison
 * is the fallback so XML bodies, where every value is text (`<match>true</match>`), still
 * match a config that wrote `equals: true`.
 */
export function isVerified(cfg: ProviderConfig, body: unknown): boolean {
  const flag = cfg.verifiedFlag;
  if (!flag) return true;
  const actual = getPath(body, flag.path);
  if (flag.equals === undefined) return Boolean(actual) && actual !== 'false';
  if (actual === flag.equals) return true;
  return String(actual).toLowerCase() === String(flag.equals).toLowerCase();
}

/** Map a response body to a NormalizedIdentity using the config's dot-path mapping. */
export function mapIdentity(
  cfg: ProviderConfig,
  code: string,
  pepper: string,
  body: unknown,
  input: FoundationalVerificationInput,
): NormalizedIdentity {
  const m = cfg.responseMapping ?? {};
  const pick = (field: keyof NormalizedIdentity): string | undefined => {
    const path = m[field];
    if (!path) return undefined;
    const v = getPath(body, path);
    return v == null ? undefined : String(v);
  };

  const rawSubjectPath = (cfg.extra?.subjectSourcePath as string) ?? undefined;
  const rawId =
    (rawSubjectPath ? String(getPath(body, rawSubjectPath) ?? '') : '') ||
    Object.values(input.identifiers)[0] ||
    '';

  return {
    subjectRef: tokenizeSubject(code, rawId, pepper),
    fullName: pick('fullName'),
    givenName: pick('givenName'),
    familyName: pick('familyName'),
    dateOfBirth: pick('dateOfBirth'),
    gender: pick('gender'),
    phone: pick('phone'),
    email: pick('email'),
    photo: pick('photo'),
    addressHint: pick('addressHint'),
    // Residence and origin are read from distinct paths and kept apart: only residence is
    // ever offered as proof-of-residence evidence downstream.
    residenceAdminUnit: pick('residenceAdminUnit'),
    originAdminUnit: pick('originAdminUnit'),
  };
}

/**
 * Applicant->identity binding, if the provider actually authenticated the owner. A plain
 * lookup (REST match, file match, XML match) attests nothing here: it leaves the binding
 * undefined so the residency engine will not mistake a matched record for a proven owner.
 * Only a provider flagged `authenticatesApplicant` (an eID/OIDC redirect, or an OTP to the
 * device registered against the record) attests `authoritative_authentication`.
 */
export function applicantBindingFrom(
  cfg: ProviderConfig,
  input: FoundationalVerificationInput,
): ApplicantBinding | undefined {
  if (!cfg.authenticatesApplicant) return undefined;
  return {
    method: 'authoritative_authentication',
    ref: input.challengeRef,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * The full REST/XML path: check the verified flag, then map. Returns a NO_MATCH result if
 * the flag fails. (DATASET_FILE does not use this -- for a file source, a found record IS
 * the match, so it maps directly.)
 */
export function resultFromBody(
  cfg: ProviderConfig,
  code: string,
  pepper: string,
  body: unknown,
  input: FoundationalVerificationInput,
): FoundationalVerificationResult {
  if (!isVerified(cfg, body)) {
    return {
      verified: false,
      providerCode: code,
      assuranceLevel: 'none',
      reason: 'FOUNDATIONAL_NO_MATCH',
    };
  }
  return {
    verified: true,
    providerCode: code,
    assuranceLevel: cfg.assuranceOnSuccess ?? 'verified',
    identity: mapIdentity(cfg, code, pepper, body, input),
    applicantBinding: applicantBindingFrom(cfg, input),
  };
}
