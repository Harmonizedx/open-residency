// SPDX-License-Identifier: Apache-2.0
import { timingSafeEqual } from 'node:crypto';

/**
 * Comparing two secrets without leaking either through timing or length.
 *
 * `a !== b` returns as soon as it finds a differing byte, so how long it takes is a function
 * of how much of the secret the caller got right — enough, over many requests, to recover it
 * a byte at a time. `timingSafeEqual` fixes that, but it throws when the two buffers differ
 * in length, and a throw is its own signal: an attacker learns the secret's length by
 * watching which requests error.
 *
 * The obvious way round that is to reduce both sides to a digest first. Two earlier versions
 * of this function did exactly that — SHA-256, then HMAC — and both are the shape of a
 * password hash whatever the intent, which is why a scanner keeps saying so. A slow KDF
 * would silence it while being the wrong instrument entirely: scrypt and argon2 defend
 * STORED, low-entropy credentials against offline attack, and they would add real latency to
 * every privileged request to defend against an attack that does not apply to a value that
 * is never written down.
 *
 * So this does not hash at all. Both sides are copied into a fixed-size frame whose first
 * four bytes are the true length, and one comparison covers the whole frame:
 *
 *   - The work is always the same, whatever either input's length, so nothing about the
 *     secret's size is observable in timing.
 *   - The length lives INSIDE the compared bytes, so two secrets of different lengths can
 *     never match — which is what a separate length check would have told an attacker.
 *   - `timingSafeEqual` never sees a length mismatch, so it cannot throw and cannot be used
 *     as an oracle.
 *
 * Secrets longer than the frame are compared on their first FRAME_BYTES bytes plus their
 * exact length. An API key long enough for that to matter has already far exceeded the
 * entropy any attacker could search, and the length prefix keeps distinct lengths distinct.
 */

/** Frame size, generous enough that no realistic key is truncated. */
const FRAME_BYTES = 1024;

function frame(secret: string): Buffer {
  const raw = Buffer.from(secret, 'utf8');
  // 4 bytes of length, then the content, zero-padded to a constant width.
  const out = Buffer.alloc(4 + FRAME_BYTES);
  out.writeUInt32BE(Math.min(raw.length, 0xffffffff), 0);
  raw.copy(out, 4, 0, Math.min(raw.length, FRAME_BYTES));
  return out;
}

export function secretsEqual(presented: string, required: string): boolean {
  return timingSafeEqual(frame(presented), frame(required));
}