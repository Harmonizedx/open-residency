/**
 * Minimal base58btc encoder with the multibase 'z' prefix used by did:key.
 * Kept dependency-free so the credential core has no heavy crypto-library tail.
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58btc(bytes: Uint8Array): string {
  // Count leading zero bytes (encoded as leading '1').
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits: number[] = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = 'z'; // multibase base58btc prefix
  for (let i = 0; i < zeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]];
  return out;
}

/**
 * Decode a multibase base58btc string (the 'z'-prefixed form produced above).
 * Needed to resolve a did:key back to raw public key bytes, which is what lets a
 * verifier check a holder's proof with no network access at all.
 */
export function base58btcDecode(encoded: string): Uint8Array {
  if (!encoded.startsWith('z')) {
    throw new Error("multibase string must start with 'z' (base58btc)");
  }
  const body = encoded.slice(1);

  let zeros = 0;
  while (zeros < body.length && body[zeros] === '1') zeros++;

  const bytes: number[] = [0];
  for (let i = zeros; i < body.length; i++) {
    const value = ALPHABET.indexOf(body[i]);
    if (value < 0) throw new Error(`invalid base58 character '${body[i]}'`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}
