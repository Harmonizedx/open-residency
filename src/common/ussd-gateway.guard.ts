import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { secretsEqual } from './api-key.guard';

/**
 * Shared-secret guard for the USSD gateway webhook.
 *
 * The webhook trusts `phoneNumber` and `sessionId` straight from the request body: that
 * is correct for a call arriving from the aggregator, which resolves the MSISDN from the
 * signalling channel, and wrong for anyone else. Without a check, whoever can reach the
 * route can drive the state machine as an arbitrary number -- triggering login codes to
 * a phone they do not hold, and standing up a lookup oracle over semi-public residency
 * IDs.
 *
 * Aggregators differ on how they authenticate their callbacks (Africa's Talking and
 * Twilio each have their own signature scheme), so this enforces the lowest common
 * denominator every one of them supports: a shared secret the aggregator is configured
 * to send back. A deployment fronting a gateway that signs its callbacks should verify
 * that signature here instead.
 */
@Injectable()
export class UssdGatewayGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const required = process.env.USSD_GATEWAY_SECRET;
    // No secret configured means the webhook cannot be authenticated at all. Refuse the
    // call rather than accept an unauthenticated one, matching AdminKeyGuard.
    if (!required) {
      throw new UnauthorizedException('USSD gateway secret not configured on this deployment');
    }
    const req = context.switchToHttp().getRequest();
    const header: string = req.headers['x-ussd-secret'] ?? req.headers['authorization'] ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : header;
    if (!presented || !secretsEqual(presented, required)) {
      throw new UnauthorizedException('Invalid or missing USSD gateway secret');
    }
    return true;
  }
}