// SPDX-License-Identifier: Apache-2.0
import {
  Body,
  Controller,
  NotFoundException,
  Post,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { NormalizedIdentity, ProviderNotConfiguredError } from '../core/foundational/types';
import { ChallengeDto, VerifyIdentityDto } from './dto/identity.dto';

// Request DTOs (validated by the global ValidationPipe) live in ./dto/identity.dto.ts.

/**
 * Identity Verification API.
 *
 * Verifies a person against the configured foundational provider and returns the
 * normalized, minimized identity plus an assurance level, WITHOUT minting a
 * residency or persisting anything. Use it for KYC-style checks, eligibility
 * pre-screening, or as the first leg of a two-step (OTP) flow. The raw national ID
 * never leaves the adapter, and only the tokenized subjectRef is returned.
 */
@Controller('identity')
export class IdentityController {
  constructor(private platform: PlatformService) {}

  @Post('challenge')
  async challenge(@Body() body: ChallengeDto) {
    const cfg = this.platform.getConfig(body.countryCode);
    if (!cfg) throw new NotFoundException(`No config for country ${body.countryCode}`);
    const provider = this.platform.getResidency().getProvider(cfg);
    const audit = this.platform.getAudit();

    if (!provider.initiateChallenge) {
      return { challengeRequired: false };
    }
    let res;
    try {
      res = await provider.initiateChallenge({
        countryCode: cfg.countryCode,
        identifiers: body.identifiers,
      });
    } catch (e) {
      throw asServiceUnavailable(e);
    }
    await audit.record({
      action: 'identity.challenge',
      actor: 'citizen',
      countryCode: cfg.countryCode,
      outcome: 'success',
      metadata: { channel: res.channel, type: res.type },
    });
    return { challengeRequired: true, challengeRef: res.challengeRef, channel: res.channel };
  }

  @Post('verify')
  async verify(@Body() body: VerifyIdentityDto) {
    const cfg = this.platform.getConfig(body.countryCode);
    if (!cfg) throw new NotFoundException(`No config for country ${body.countryCode}`);
    const provider = this.platform.getResidency().getProvider(cfg);
    const audit = this.platform.getAudit();

    let result;
    try {
      result = await provider.verify({
        countryCode: cfg.countryCode,
        identifiers: body.identifiers,
        challengeRef: body.challengeRef,
      });
    } catch (e) {
      throw asServiceUnavailable(e);
    }

    if (!result.verified && result.pendingChallenge) {
      return {
        verified: false,
        pendingChallenge: true,
        challengeRef: result.pendingChallenge.challengeRef,
        channel: result.pendingChallenge.channel,
      };
    }

    await audit.record({
      action: 'identity.verify',
      actor: 'citizen',
      target: result.identity?.subjectRef,
      countryCode: cfg.countryCode,
      outcome: result.verified ? 'success' : 'failure',
      metadata: { provider: cfg.foundational.provider, purpose: body.purpose },
    });

    return {
      verified: result.verified,
      assuranceLevel: result.assuranceLevel,
      subjectRef: result.identity?.subjectRef,
      // Minimized attributes only. No raw national ID is ever present here.
      attributes: minimize(result.identity),
      reason: result.verified ? undefined : result.reason,
    };
  }
}

/**
 * A provider the deployment named but did not finish configuring is a 503, not a 500.
 *
 * 500 reads as "try again" and buries the message; 503 says the route exists and this
 * deployment has not configured it, which is the same answer UpstreamController gives when
 * no upstreamOidc profile is declared. Anything else is a genuine fault and is left alone.
 */
function asServiceUnavailable(e: unknown): unknown {
  return e instanceof ProviderNotConfiguredError ? new ServiceUnavailableException(e.message) : e;
}

function minimize(identity?: NormalizedIdentity): Record<string, unknown> {
  if (!identity) return {};
  const { subjectRef, photo, ...rest } = identity;
  return Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined));
}
