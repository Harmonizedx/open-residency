// SPDX-License-Identifier: Apache-2.0
import { Injectable, Logger } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request } from 'express';
import { callerKey } from '../core/ratelimit/caller-key';

/** Declared by the deployment; 0 means the application is exposed directly (ADR-0013). */
export function trustedProxyHops(): number {
  const raw = Number(process.env.TRUSTED_PROXY_HOPS ?? 0);
  return Number.isFinite(raw) && raw > 0 ? Math.trunc(raw) : 0;
}

/**
 * Rate limiting that counts the caller rather than whatever proxy forwarded them (ADR-0013).
 *
 * The stock tracker keys on `req.ip`, which behind the ingress this project documents is the
 * ingress pod for every request -- one bucket for the whole deployment. The decision of what
 * to count lives in `core/ratelimit/caller-key.ts`; this reads the request and reports the
 * mismatch.
 */
@Injectable()
export class CallerThrottlerGuard extends ThrottlerGuard {
  private readonly log = new Logger('RateLimit');
  private warned = false;

  protected async getTracker(req: Record<string, unknown>): Promise<string> {
    const r = req as unknown as Request;

    // No credential is read here. This guard is global, so it runs BEFORE OperatorGuard: any
    // credential on the request is an unverified string at this point, and keying on one
    // would let an anonymous caller rotate a header to get a fresh budget per request.
    const forwardedFor = r.headers?.['x-forwarded-for'];
    const decided = callerKey({
      // Duplicate header instances: the later ones were appended by the proxies we trust, so
      // preserve the whole chain rather than keeping the caller-supplied first.
      forwardedFor: Array.isArray(forwardedFor) ? forwardedFor.join(', ') : forwardedFor,
      remoteAddress: r.ip ?? r.socket?.remoteAddress,
      trustedHops: trustedProxyHops(),
    });

    // Once, loudly. The defect this replaces survived because it failed silently and looked
    // correct: the only symptom was unexplained 429s under load, which reads as "the limit is
    // too low" -- and raising it widens the hole.
    if (decided.proxyMismatch && !this.warned) {
      this.warned = true;
      this.log.warn(
        'Requests carry X-Forwarded-For but TRUSTED_PROXY_HOPS is 0, so anonymous rate ' +
          'limiting is counting the proxy and not the caller: one shared budget for every ' +
          'client behind it. Set TRUSTED_PROXY_HOPS to the number of proxies in front of ' +
          'this service (see docs/DEPLOY.md and ADR-0013).',
      );
    }
    return decided.key;
  }
}
