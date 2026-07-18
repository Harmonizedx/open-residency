import { ContactDirectory, MessagingProvider, maskPhone } from './types';
import type { OtpSender } from '../sso/otp';

/**
 * The OtpSender the platform actually wires: resolve the resident's number through the
 * contact directory, then hand the message to the configured aggregator.
 *
 * Two properties matter here and are easy to get wrong:
 *
 * 1. The code is never logged. Only the masked destination and the resulting channel are.
 *    The whole point of replacing the previous logging stub was to stop live one-time
 *    codes appearing in the service log, so this module must not reintroduce them -- not
 *    in a success line, and not in an error path.
 *
 * 2. A delivery failure is not silently swallowed. It raises, so the caller records a
 *    failed audit event and the citizen is told to try again, rather than being left
 *    waiting for a code that was never sent. The controller above still answers the
 *    citizen identically whether or not the residency ID exists, so this does not
 *    reintroduce an enumeration oracle.
 */
export class MessagingOtpSender implements OtpSender {
  constructor(
    private provider: MessagingProvider,
    private directory: ContactDirectory,
    private messageTemplate = 'Your {issuer} sign-in code is {code}. It expires in 5 minutes. Do not share it.',
    private issuerName = 'OpenResidency',
  ) {}

  async send(residentId: string, code: string): Promise<{ channel: string }> {
    const to = await this.directory.lookup(residentId);
    if (!to) {
      // No number on file. This is a configuration or enrolment gap, not an attack, and it
      // is worth surfacing loudly -- otherwise sign-in fails for that citizen with no
      // explanation anywhere.
      // eslint-disable-next-line no-console
      console.warn(
        `[otp] No contact number for resident ${residentId}; one-time code not sent. ` +
          `Check the contact directory configuration.`,
      );
      throw new Error('NO_CONTACT_ON_FILE');
    }

    const body = this.messageTemplate
      .replace(/\{code\}/g, code)
      .replace(/\{issuer\}/g, this.issuerName);

    const result = await this.provider.send({ to, body, kind: 'otp' });
    // eslint-disable-next-line no-console
    console.log(
      `[otp] code delivered to ${maskPhone(to)} via ${result.channel}` +
        (result.providerMessageId ? ` (id ${result.providerMessageId})` : ''),
    );
    return { channel: result.channel };
  }
}
