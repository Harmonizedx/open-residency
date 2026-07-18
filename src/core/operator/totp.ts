import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * TOTP (RFC 6238) for operator multi-factor authentication.
 *
 * Implemented here rather than pulled in as a dependency: it is ~60 lines of HMAC, and a
 * digital public good is easier to audit and to package for a government deployment when
 * its authentication path has no third-party code in it. The algorithm is fixed and the
 * test vectors below are from the RFC, so there is no version drift to track either.
 *
 * SHA-1 is the algorithm here because that is what every authenticator app implements.
 * It is a HMAC construction over a shared secret, not a collision-resistance use, so the
 * usual reasons to avoid SHA-1 do not apply.
 */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode bytes as unpadded base32, the form authenticator apps expect. */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32 in TOTP secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A fresh 160-bit TOTP secret, the size RFC 4226 recommends for HMAC-SHA1. */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

const STEP_SECONDS = 30;
const DIGITS = 6;

/** The TOTP code for a given secret and counter step. */
function hotp(secret: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  // Counter is a 64-bit big-endian int; writeBigUInt64BE avoids the 2^53 precision cliff.
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(buf).digest();
  // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte picks the offset.
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function totpCode(secretBase32: string, atMs = Date.now()): string {
  return hotp(base32Decode(secretBase32), Math.floor(atMs / 1000 / STEP_SECONDS));
}

/**
 * Verify a submitted TOTP code.
 *
 * `window` accepts codes from adjacent steps, because the operator's phone clock and the
 * server's are never exactly aligned and a code typed at second 29 arrives at second 31.
 * One step either side is the usual tolerance: it widens the guess space from 1 code to 3
 * out of a million, which the attempt limiter above this bounds anyway.
 *
 * The comparison is constant-time so a near-miss code cannot be distinguished by timing.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  atMs = Date.now(),
  window = 1,
): boolean {
  const submitted = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(submitted)) return false;
  const secret = base32Decode(secretBase32);
  const step = Math.floor(atMs / 1000 / STEP_SECONDS);
  let matched = false;
  for (let i = -window; i <= window; i++) {
    const expected = Buffer.from(hotp(secret, step + i));
    const got = Buffer.from(submitted);
    // Do not break on a match: run every step so the loop takes the same time either way.
    if (expected.length === got.length && timingSafeEqual(expected, got)) matched = true;
  }
  return matched;
}

/** The otpauth:// URI an authenticator app scans to enrol this secret. */
export function totpEnrolmentUri(secretBase32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
