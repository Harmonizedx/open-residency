import { Body, Controller, Header, Post, UseGuards } from '@nestjs/common';
import { UssdGatewayGuard } from '../common/ussd-gateway.guard';
import { PlatformService } from '../platform/platform.service';
import { encodeCredentialQr } from '../core/offline/qr';
import { handleUssd } from '../core/offline/ussd';
import { shortHash } from '../core/foundational/util';

/**
 * Inclusion endpoints for low- and no-connectivity contexts.
 */
@Controller('offline')
export class OfflineController {
  constructor(private platform: PlatformService) {}

  /** Render a credential as an offline-carriable QR (SVG). */
  @Post('qr')
  @Header('content-type', 'application/json')
  async qr(@Body() body: { credential: string; residentId: string }) {
    const qr = await encodeCredentialQr(body.credential, {
      residentId: body.residentId,
      integrity: shortHash(body.credential),
    });
    return { mode: qr.mode, svg: qr.svg };
  }

  /**
   * USSD gateway webhook. Adapts a generic gateway payload (sessionId, phoneNumber,
   * text) to the pure state machine, then performs any side effect (lookup / OTP).
   * Response body follows the common CON/END convention used by African aggregators.
   *
   * Gateway-guarded: the handler trusts the caller's word for `phoneNumber`, so only the
   * aggregator may call it. See UssdGatewayGuard.
   */
  @UseGuards(UssdGatewayGuard)
  @Post('ussd')
  @Header('content-type', 'text/plain')
  async ussd(@Body() body: { sessionId?: string; phoneNumber?: string; text?: string }) {
    const result = handleUssd(body.text ?? '');

    if (result.action?.type === 'lookupResident') {
      // The outcome goes out by SMS to the number registered against the record, never
      // back down the USSD session.
      //
      // Returning the status inline made this an open oracle: residency IDs are
      // semi-public (printed on cards, carried in QR codes), and anyone who could reach
      // the gateway could confirm whether any given ID existed and whether it was
      // provisional. The OTP branch below already declines to leak that, and the SSO
      // login path takes deliberate care not to enumerate residents; this now matches.
      const record = await this.platform.getStore().findByResidentId(result.action.residentId);
      if (record) {
        await this.platform.notify(
          record.residentId,
          `Your residency ${record.residentId} is ${record.provisional ? 'provisional' : 'active'} ` +
            `in ${record.subnationalUnit}.`,
        );
      }
      // Answered identically either way: the reply must not reveal whether the ID exists,
      // nor whether a message was actually dispatched.
      return `END If that residency ID is registered, its status will be sent by SMS to the registered number.`;
    }

    if (result.action?.type === 'sendOtp') {
      // Issue a real one-time code through the same OTP service the web sign-in uses, so
      // a code obtained over USSD is redeemable at the SSO login step. This used to be a
      // comment and a reassuring message -- the citizen was told a code had been sent when
      // nothing had been generated at all.
      try {
        await this.platform.getSsoAuth().beginOtpLogin(result.action.residentId);
      } catch {
        // Unknown resident, no contact on file, or an aggregator failure. Swallowed on
        // purpose: distinguishing them here would rebuild the enumeration oracle the
        // lookup branch above was fixed to remove.
      }
      return `END If that residency ID is registered, a login code has been sent by SMS to the registered number.`;
    }

    return `${result.continueSession ? 'CON' : 'END'} ${result.message}`;
  }
}
