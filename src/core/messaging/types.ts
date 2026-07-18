/**
 * Message delivery: getting a one-time code or a status notice to a citizen's phone.
 *
 * This used to be a stub that printed the code to the service log, which meant the
 * fallback sign-in factor was not a factor at all in any deployment that had not written
 * its own sender. It also meant anyone with log access could read live codes.
 *
 * The shape here mirrors the foundational-ID adapters: a small set of provider codes, a
 * config-driven generic HTTP adapter that covers any aggregator with a REST endpoint, and
 * thin presets for the aggregators a deployment in this region is actually likely to use.
 * Adding an aggregator with a normal REST API needs no code change -- the same promise
 * the country configs already make about national ID providers.
 */

export type MessagingProviderCode =
  | 'LOG'
  | 'GENERIC_HTTP'
  | 'AFRICASTALKING'
  | 'TWILIO'
  | 'TERMII';

/** A message bound for one recipient. */
export interface OutboundMessage {
  /** E.164 destination, resolved by the contact directory. Never persisted in plaintext. */
  to: string;
  body: string;
  /**
   * What this message is. Aggregators route transactional and promotional traffic
   * differently, and a one-time code must go down the transactional route or it can be
   * delayed by minutes -- long enough for the code to expire before it lands.
   */
  kind: 'otp' | 'notification';
}

export interface DeliveryResult {
  /** The channel used, recorded against the OTP challenge for the audit trail. */
  channel: string;
  /** The aggregator's own message id, when it returns one. Useful for delivery disputes. */
  providerMessageId?: string;
}

export class MessagingError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
  }
}

export interface MessagingProvider {
  readonly code: MessagingProviderCode;
  send(message: OutboundMessage): Promise<DeliveryResult>;
}

/**
 * Resolves a resident to a phone number at the moment of sending.
 *
 * This exists because of a constraint the rest of the system imposes: OpenResidency does
 * not keep plaintext phone numbers. The Resident row holds only a phoneHash, which is
 * one-way and cannot be dialled. So delivery needs an explicit, auditable step that turns
 * a residentId into a number, and that step is the natural place for a deployment to
 * point at whatever contact directory it already runs.
 */
export interface ContactDirectory {
  /** The resident's E.164 number, or null if none is known. */
  lookup(residentId: string): Promise<string | null>;
}

/** Redact a number for logs: keep the country prefix and last two digits, mask the rest. */
export function maskPhone(e164: string): string {
  if (e164.length < 6) return '***';
  return `${e164.slice(0, 4)}${'*'.repeat(Math.max(0, e164.length - 6))}${e164.slice(-2)}`;
}
