// SPDX-License-Identifier: Apache-2.0
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Comparing two secrets without leaking either through timing or length.
 *
 * `a !== b` returns as soon as it finds a differing byte, so how long it takes is a function
 * of how much of the secret the caller got right — enough, over many requests, to recover it
 * a byte at a time. `timingSafeEqual` fixes that but throws on a length mismatch, which is
 * itself an oracle: an attacker learns the secret's length by watching which requests error.
 *
 * So both sides are reduced to a fixed 32 bytes first. The reduction is an HMAC under a key
 * generated once per process, NOT a bare digest, and the difference matters in two ways:
 *
 *   - A bare SHA-256 of a credential is a password hash by any other name: it is offline-
 *     crackable, because the attacker can compute candidates themselves. Under a random key
 *     they cannot, since they do not have the key — the digest is worth nothing outside this
 *     process, and the process never stores or transmits it.
 *   - It is honest about what this is. Nothing here is a stored credential, so a slow KDF
 *     (scrypt, argon2) would be the wrong tool: it would cost every request real time to
 *     defend against an offline attack that a per-process key already prevents.
 *
 * The key never leaves memory and is not derivable from anything on disk, so a restart
 * simply produces different digests — which is fine, because nothing compares them across
 * restarts.
 */
const COMPARISON_KEY = randomBytes(32);

export function secretsEqual(presented: string, required: string): boolean {
  const a = createHmac('sha256', COMPARISON_KEY).update(presented).digest();
  const b = createHmac('sha256', COMPARISON_KEY).update(required).digest();
  return timingSafeEqual(a, b);
}