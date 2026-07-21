import { createHash, createHmac } from 'node:crypto';

/**
 * AWS Signature Version 4, enough of it to call KMS.
 *
 * Hand-rolled rather than pulled from the AWS SDK for the same reason the KMS adapter
 * is: the SDK is a large dependency tree for two API calls, and a government deployment
 * auditing what signs its credentials is better served by ~80 readable lines than by a
 * transitive graph. This implements the JSON-protocol subset only (POST to `/`, no query
 * string, no chunked payloads), which is all KMS needs.
 */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const sha256Hex = (data: string | Buffer): string =>
  createHash('sha256').update(data).digest('hex');
const hmac = (key: Buffer | string, data: string): Buffer =>
  createHmac('sha256', key).update(data, 'utf8').digest();

/** `20260720T134501Z` and `20260720`, the two timestamp forms SigV4 uses. */
export function sigv4Timestamps(now: Date): { amzDate: string; dateStamp: string } {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

/**
 * Build the headers for a signed KMS request.
 *
 * Header ORDER and CASE are load-bearing: the canonical request requires headers
 * lowercased and sorted by name, and the signature covers exactly the set named in
 * SignedHeaders. Adding a header to the request without adding it here (or vice versa)
 * produces a signature mismatch that AWS reports only as a generic 403.
 */
export function signRequest(opts: {
  credentials: AwsCredentials;
  region: string;
  service: string;
  host: string;
  target: string;
  body: string;
  now?: Date;
}): Record<string, string> {
  const { credentials, region, service, host, target, body } = opts;
  const { amzDate, dateStamp } = sigv4Timestamps(opts.now ?? new Date());

  const contentType = 'application/x-amz-json-1.1';
  const headers: Record<string, string> = {
    'content-type': contentType,
    host,
    'x-amz-date': amzDate,
    'x-amz-target': target,
  };
  if (credentials.sessionToken) headers['x-amz-security-token'] = credentials.sessionToken;

  const sortedNames = Object.keys(headers).sort();
  const canonicalHeaders = sortedNames.map((n) => `${n}:${headers[n].trim()}\n`).join('');
  const signedHeaders = sortedNames.join(';');

  const canonicalRequest = [
    'POST',
    '/',
    '', // no query string
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, dateStamp), region), service),
    'aws4_request',
  );
  const signature = createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

  return {
    ...headers,
    authorization:
      `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}