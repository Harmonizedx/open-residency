import QRCode from 'qrcode';

/**
 * Encodes a residency Verifiable Credential into a QR code for offline carriage.
 *
 * Because we sign with Ed25519 and use the compact VC-JWT format, a full residency
 * credential is typically under ~1.2 KB, which fits inside a single QR code in byte
 * mode. A holder can therefore carry their credential on paper or on a basic phone
 * screen and present it where there is no connectivity; the verifier scans and
 * checks it against a cached issuer key with no network call.
 *
 * If a credential ever exceeds the single-QR budget, we fall back to an offline
 * "pointer" QR: the human residentId plus an integrity hash, which a verifier can
 * confirm against a synced snapshot rather than online.
 */

// A version-40 QR in byte mode holds up to 2331 bytes at EC level M. We keep a
// little headroom below that so cheap cameras still lock focus; above it we switch
// to the pointer form. A typical Ed25519 residency VC-JWT (~1.9 KB) fits comfortably.
const SINGLE_QR_BUDGET = 2200;

export interface QrResult {
  mode: 'full' | 'pointer';
  svg: string;
  payload: string;
}

export async function encodeCredentialQr(
  jwt: string,
  fallback: { residentId: string; integrity: string },
): Promise<QrResult> {
  if (jwt.length <= SINGLE_QR_BUDGET) {
    const payload = `openres:vc:${jwt}`;
    const svg = await QRCode.toString(payload, {
      type: 'svg',
      errorCorrectionLevel: 'M',
      margin: 1,
    });
    return { mode: 'full', svg, payload };
  }

  const payload = `openres:ref:${fallback.residentId}:${fallback.integrity}`;
  const svg = await QRCode.toString(payload, {
    type: 'svg',
    errorCorrectionLevel: 'Q',
    margin: 1,
  });
  return { mode: 'pointer', svg, payload };
}

/** Parse a scanned OpenResidency QR payload back into its parts. */
export function parseQrPayload(
  payload: string,
): { kind: 'vc'; jwt: string } | { kind: 'ref'; residentId: string; integrity: string } | null {
  if (payload.startsWith('openres:vc:')) {
    return { kind: 'vc', jwt: payload.slice('openres:vc:'.length) };
  }
  if (payload.startsWith('openres:ref:')) {
    const [, , residentId, integrity] = payload.split(':');
    return { kind: 'ref', residentId, integrity };
  }
  return null;
}
