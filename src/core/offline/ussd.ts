// SPDX-License-Identifier: Apache-2.0
/**
 * USSD state machine for feature phones (no smartphone, no data plan).
 *
 * USSD works on the most basic GSM handsets over signalling channels, so it reaches
 * residents that app- or web-based flows never will. This module is a pure reducer:
 * given the accumulated user input string (as most USSD gateways deliver it, e.g.
 * "1*KT*7F3A") it returns the next menu text and whether the session continues.
 *
 * The gateway-specific controller (Africa's Talking, Twilio, an MNO aggregator)
 * simply adapts its request shape to `handleUssd` and maps the reply to CON/END.
 *
 * What a resident can do here without any internet:
 *   1. Check whether they already hold residency (by residentId).
 *   2. Trigger an SMS one-time verification code a service can use to prove they
 *      control the phone bound to their residency (a lightweight, offline-friendly
 *      authentication factor that does not require the SSO web flow).
 *   3. See who has looked at their record, answered inline on the SIM's own authority,
 *      with no message sent and nothing paid for.
 */

export interface UssdResult {
  message: string;
  continueSession: boolean;
  /** Side effect the controller should perform, if any. */
  action?:
    | { type: 'lookupResident'; residentId: string }
    | { type: 'sendOtp'; residentId: string }
    /**
     * Who has looked at my record. Answered INLINE, not by SMS, because the USSD session is
     * attributed by the network to the SIM that dialled, and the controller only answers when
     * that SIM is the one registered against the record. No message is sent and nothing is
     * paid for; the summary is a few lines of menu text.
     */
    | { type: 'accessLogSummary'; residentId: string };
}

export function handleUssd(text: string): UssdResult {
  const parts = text.split('*').filter((p) => p !== '');

  // Top-level menu.
  if (parts.length === 0) {
    return {
      continueSession: true,
      message: [
        'OpenResidency',
        '1. Check my residency status',
        '2. Get a login code',
        '3. Who has looked at my record',
      ].join('\n'),
    };
  }

  const choice = parts[0];

  if (choice === '1') {
    if (parts.length === 1) {
      return { continueSession: true, message: 'Enter your Residency ID (e.g. KT-7F3A-9K2P-4):' };
    }
    const residentId = parts.slice(1).join('*').toUpperCase();
    return {
      continueSession: false,
      message: 'Checking your residency status. We will confirm by SMS shortly.',
      action: { type: 'lookupResident', residentId },
    };
  }

  if (choice === '2') {
    if (parts.length === 1) {
      return { continueSession: true, message: 'Enter your Residency ID to receive a login code:' };
    }
    const residentId = parts.slice(1).join('*').toUpperCase();
    return {
      continueSession: false,
      message: 'A one-time login code has been sent to your registered phone.',
      action: { type: 'sendOtp', residentId },
    };
  }

  if (choice === '3') {
    if (parts.length === 1) {
      return { continueSession: true, message: 'Enter your Residency ID to see who has looked at your record:' };
    }
    const residentId = parts.slice(1).join('*').toUpperCase();
    return {
      continueSession: false,
      // The controller replaces this text with the summary when the dialling SIM is the
      // registered one; otherwise this generic line is what is shown, identically for an
      // unknown id and for a known id dialled from another phone.
      message: 'If that residency ID is registered to this phone, its access summary is shown here.',
      action: { type: 'accessLogSummary', residentId },
    };
  }
  return { continueSession: false, message: 'Invalid choice. Dial again to retry.' };
}

/**
 * The access log as a few lines of USSD text. Counts by kind of actor, and the most recent
 * access, because a USSD screen holds about 160 characters and a resident on a feature phone
 * wants the answer to "has anyone been looking at my record" rather than a table.
 */
export function accessLogUssdSummary(
  entries: ReadonlyArray<{ at: string; actorKind: string; relyingParty?: string }>,
): string {
  if (entries.length === 0) return 'No one has looked at your record.';
  const counts = new Map<string, number>();
  for (const e of entries) {
    const k = e.actorKind === 'relying_party' ? `service ${e.relyingParty ?? ''}`.trim() : e.actorKind.replace('_', ' ');
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const last = entries[entries.length - 1];
  const lines = [`${entries.length} access(es) to your record.`];
  for (const [k, n] of counts) lines.push(`${n} by ${k}`);
  lines.push(`Last: ${last.at.slice(0, 10)}`);
  return lines.join('\n').slice(0, 160);
}
