import { Body, Controller, Header, Post } from '@nestjs/common';
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
   */
  @Post('ussd')
  @Header('content-type', 'text/plain')
  async ussd(@Body() body: { sessionId?: string; phoneNumber?: string; text?: string }) {
    const result = handleUssd(body.text ?? '');

    if (result.action?.type === 'lookupResident') {
      const rec = await this.platform.getStore().findByResidentId(result.action.residentId);
      // In production, dispatch an SMS with the outcome via the SMS provider here.
      const status = rec ? (rec.provisional ? 'PROVISIONAL' : 'ACTIVE') : 'NOT_FOUND';
      return `END Residency ${result.action.residentId}: ${status}`;
    }

    if (result.action?.type === 'sendOtp') {
      // In production, generate + persist an OtpChallenge and send via SMS.
      // The resulting code can then be exchanged at the SSO token endpoint as an
      // offline-friendly authentication factor.
      return `END A login code has been sent by SMS to your registered number.`;
    }

    return `${result.continueSession ? 'CON' : 'END'} ${result.message}`;
  }
}
