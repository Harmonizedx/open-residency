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
 */

export interface UssdResult {
  message: string;
  continueSession: boolean;
  /** Side effect the controller should perform, if any. */
  action?:
    | { type: 'lookupResident'; residentId: string }
    | { type: 'sendOtp'; residentId: string };
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

  return { continueSession: false, message: 'Invalid choice. Dial again to retry.' };
}
