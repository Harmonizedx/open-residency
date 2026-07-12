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
 * Encoding per spec: raw bits -> GZIP -> base64url.
 */
export class StatusList {
  private bits: Uint8Array;
  constructor(public readonly sizeBits = 131072 /* 16 KB of bits */) {
    this.bits = new Uint8Array(Math.ceil(sizeBits / 8));
  }

  static fromEncoded(encoded: string, sizeBits?: number): StatusList {
    const raw = gunzipSync(Buffer.from(encoded, 'base64url'));
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
    return gzipSync(Buffer.from(this.bits)).toString('base64url');
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
