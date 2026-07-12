import { Body, Controller, NotFoundException, Post } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { NormalizedIdentity } from '../core/foundational/types';

interface VerifyIdentityBody {
  countryCode: string;
  identifiers: Record<string, string>;
  challengeRef?: string;
  purpose?: string;
}

interface ChallengeBody {
  countryCode: string;
  identifiers: Record<string, string>;
}

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
  async challenge(@Body() body: ChallengeBody) {
    const cfg = this.platform.getConfig(body.countryCode);
    if (!cfg) throw new NotFoundException(`No config for country ${body.countryCode}`);
    const provider = this.platform.getResidency().getProvider(cfg);
    const audit = this.platform.getAudit();

    if (!provider.initiateChallenge) {
      return { challengeRequired: false };
    }
    const res = await provider.initiateChallenge({
      countryCode: cfg.countryCode,
      identifiers: body.identifiers,
    });
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
  async verify(@Body() body: VerifyIdentityBody) {
    const cfg = this.platform.getConfig(body.countryCode);
    if (!cfg) throw new NotFoundException(`No config for country ${body.countryCode}`);
    const provider = this.platform.getResidency().getProvider(cfg);
    const audit = this.platform.getAudit();

    const result = await provider.verify({
      countryCode: cfg.countryCode,
      identifiers: body.identifiers,
      challengeRef: body.challengeRef,
    });

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

function minimize(identity?: NormalizedIdentity): Record<string, unknown> {
  if (!identity) return {};
  const { subjectRef, photo, ...rest } = identity;
  return Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined));
}
