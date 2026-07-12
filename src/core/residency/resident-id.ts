import { createHash, randomBytes } from 'node:crypto';

/**
 * Human-facing Residency ID, e.g. KT-7F3A-9K2P-4.
 *
 * Structure: <UNIT>-<block>-<block>-<checkDigit>. Uses Crockford base32 (no I/L/O/U)
 * so it is easy to read aloud, dictate over a phone line, and print. The trailing
 * check digit catches transcription errors when an operator keys it in.
 */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function toCrockford(bytes: Buffer, length: number): string {
  let out = '';
  for (let i = 0; i < length; i++) out += CROCKFORD[bytes[i] % 32];
  return out;
}

function checkChar(payload: string): string {
  const sum = createHash('sha256').update(payload).digest()[0];
  return CROCKFORD[sum % 32];
}

export function generateResidentId(unitCode: string): string {
  const b = randomBytes(8);
  const a = toCrockford(b.subarray(0, 4), 4);
  const c = toCrockford(b.subarray(4, 8), 4);
  const core = `${unitCode.toUpperCase()}-${a}-${c}`;
  return `${core}-${checkChar(core)}`;
}

export function isValidResidentId(id: string): boolean {
  const idx = id.lastIndexOf('-');
  if (idx < 0) return false;
  const core = id.slice(0, idx);
  const check = id.slice(idx + 1);
  return check === checkChar(core);
}
