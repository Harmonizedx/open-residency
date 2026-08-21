// SPDX-License-Identifier: Apache-2.0
import {
  Body,
  Controller,
  NotFoundException,
  Post,
  Req,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import {
  OperatorGuard,
  RequireRoles,
  RequestWithOperator,
  requireOperator,
} from '../common/operator.guard';
import { operatorActor } from '../core/operator/operator';
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

  /**
   * Begin a two-step verification against the configured provider.
   *
   * Operator-guarded. For a provider that authenticates by redirect, this mints a state,
   * nonce and PKCE verifier and writes a pending row -- so an unauthenticated caller could
   * otherwise drive authorization requests at the jurisdiction's own identity provider on its
   * behalf, and accumulate pending state doing it. `POST /enrolment/upstream/start` performs
   * the same act and has carried this guard for exactly that reason; leaving this one open
   * would have made the guard there decorative.
   *
   * `registrar` rather than `admin`: beginning a verification is enrolment-desk work, and the
   * role that may complete an enrolment is the one that may start one.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('challenge')
  async challenge(@Req() req: RequestWithOperator, @Body() body: ChallengeDto) {
    const operator = requireOperator(req);
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
      // The route is operator-only, so the trail names the operator. 'citizen' would
      // attribute the lookup to a party who cannot have made the call -- and this log is the
      // only place that can answer who asked the register about a named person.
      actor: operatorActor(operator),
      countryCode: cfg.countryCode,
      outcome: 'success',
      metadata: { channel: res.channel, type: res.type },
    });
    return { challengeRequired: true, challengeRef: res.challengeRef, channel: res.channel };
  }

  /**
   * Operator-guarded for the same reason as `challenge`, and for one more: this asks the
   * jurisdiction's register about a named person and returns their attributes. Guarding only
   * the first step would leave the lookup itself open, which is the part that reads somebody
   * else's identity.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('verify')
  async verify(@Req() req: RequestWithOperator, @Body() body: VerifyIdentityDto) {
    const operator = requireOperator(req);
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
      actor: operatorActor(operator),
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
