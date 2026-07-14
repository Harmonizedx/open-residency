import { gzipSync, gunzipSync } from 'node:zlib';

/**
 * Bitstring Status List (W3C Bitstring Status List v1.0, simplified).
 *
 * Each issued credential is assigned an index into a large bitstring. Bit 0 means
 * active, bit 1 means revoked/suspended. The encoded list is published once and can
 * be cached by verifiers, so revocation checking works offline against the last
 * synced snapshot. This avoids per-credential online status calls, which is exactly
 * what low-connectivity deployments need.
 *
 * Encoding per spec: raw bits -> GZIP -> base64url -> multibase.
 *
 * Note the last step. The spec requires `encodedList` to be a MULTIBASE-encoded base64url
 * string, which carries a leading 'u' identifying the base. We previously emitted bare
 * base64url. That reads correctly to a human and fails a strict verifier, which would take
 * the leading 'H' of the GZIP magic bytes as the multibase identifier and decode garbage.
 */

/** Multibase prefix for base64url, unpadded. */
const MULTIBASE_BASE64URL = 'u';

export class StatusList {
  private bits: Uint8Array;
  constructor(public readonly sizeBits = 131072 /* 16 KB of bits: the spec minimum */) {
    this.bits = new Uint8Array(Math.ceil(sizeBits / 8));
  }

  static fromEncoded(encoded: string, sizeBits?: number): StatusList {
    // Accept both the conformant multibase form and the bare base64url we used to emit, so
    // that status lists already published by a running deployment keep decoding after an
    // upgrade. Revocation data that silently stops loading is revocation that stops being
    // enforced, which is the worst possible way for this to fail.
    const body = encoded.startsWith(MULTIBASE_BASE64URL) ? encoded.slice(1) : encoded;
    const raw = gunzipSync(Buffer.from(body, 'base64url'));
    const list = new StatusList(sizeBits ?? raw.length * 8);
    list.bits = new Uint8Array(raw);
    return list;
  }

  private assertIndex(index: number): void {
    if (index < 0 || index >= this.sizeBits) {
      throw new Error(`status index ${index} out of range`);
    }
  }

  set(index: number, revoked: boolean): void {
    this.assertIndex(index);
    const byte = index >> 3;
    const bit = 7 - (index & 7);
    if (revoked) this.bits[byte] |= 1 << bit;
    else this.bits[byte] &= ~(1 << bit);
  }

  isRevoked(index: number): boolean {
    this.assertIndex(index);
    const byte = index >> 3;
    const bit = 7 - (index & 7);
    return (this.bits[byte] & (1 << bit)) !== 0;
  }

  encode(): string {
    return MULTIBASE_BASE64URL + gzipSync(Buffer.from(this.bits)).toString('base64url');
  }

  /** Publish as a StatusList credential subject body, ready to be signed as a VC. */
  toCredentialSubject(id: string, purpose: 'revocation' | 'suspension' = 'revocation') {
    return {
      id: `${id}#list`,
      type: 'BitstringStatusList',
      statusPurpose: purpose,
      encodedList: this.encode(),
    };
  }
}
