// SPDX-License-Identifier: Apache-2.0
import { Body, Controller, Header, Post, UseGuards } from '@nestjs/common';
import { UssdGatewayGuard } from '../common/ussd-gateway.guard';
import { PlatformService } from '../platform/platform.service';
import { encodeCredentialQr } from '../core/offline/qr';
import { accessLogUssdSummary, handleUssd } from '../core/offline/ussd';
import { accessLogFor } from '../core/audit/access-log';
import { createHash } from 'node:crypto';
import { shortHash } from '../core/foundational/util';
import { QrDto, UssdDto } from './dto/offline.dto';

/**
 * Inclusion endpoints for low- and no-connectivity contexts.
 */
@Controller('offline')
export class OfflineController {
  constructor(private platform: PlatformService) {}

  /** Render a credential as an offline-carriable QR (SVG). */
  @Post('qr')
  @Header('content-type', 'application/json')
  async qr(@Body() body: QrDto) {
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
  async ussd(@Body() body: UssdDto) {
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

    if (result.action?.type === 'accessLogSummary') {
      // Answered on the SIM's own authority. The network attributed this session to
      // `phoneNumber`; the register holds the hash of the number registered against the
      // record; when they are the same SIM the summary is shown inline and nothing is sent
      // or paid for. Any other case -- unknown id, known id dialled from another phone, the
      // factor disabled on this deployment -- gets the reducer's generic line, identically.
      const factors = this.platform.listConfigs()[0]?.selfService.accessLogFactors ?? [];
      const e164 = normaliseE164(body.phoneNumber);
      if (factors.includes('ussd') && e164) {
        const record = await this.platform
          .getStore()
          .findByPhoneHash(createHash('sha256').update(e164).digest('hex'));
        if (record && record.residentId === result.action.residentId) {
          const audit = this.platform.getAudit();
          const entries = await accessLogFor(audit, record.residentId);
          await audit.record({
            action: 'resident.access.read',
            actor: record.residentId,
            target: record.residentId,
            outcome: 'success',
            metadata: { entries: entries.length, factor: 'ussd' },
          });
          return `END ${accessLogUssdSummary(entries)}`;
        }
      }
      return `END ${result.message}`;
    }

    return `${result.continueSession ? 'CON' : 'END'} ${result.message}`;
  }
}

/**
 * The form `recordContact` hashed: E.164 with a leading plus. Aggregators commonly deliver the
 * number without the plus, so one is restored when the rest is a plausible international
 * number; anything else is not matched at all, rather than guessed at.
 */
function normaliseE164(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const t = raw.trim();
  const withPlus = t.startsWith('+') ? t : `+${t}`;
  return /^\+[1-9]\d{6,14}$/.test(withPlus) ? withPlus : undefined;
}
