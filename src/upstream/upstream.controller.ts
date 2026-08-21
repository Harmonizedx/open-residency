// SPDX-License-Identifier: Apache-2.0
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Query,
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

/**
 * Signing a resident in at their jurisdiction's own identity provider, before enrolling them.
 *
 * A jurisdiction whose residents already hold a national identity — a MOSIP eSignet instance,
 * a national eID — should not make them prove themselves twice at the residency desk. The
 * result is worth more than a registry lookup: a lookup only shows a record exists, and
 * anyone holding the number passes it, whereas an upstream sign-in is the source itself
 * confirming the owner was present. That is `authoritative_authentication`, the strongest
 * binding in core/proofing/binding.ts.
 *
 * The output of this flow is an ApplicantBinding, which is exactly what `POST /residency/issue`
 * already accepts as `binding` and combines with whatever the provider attested. So this adds
 * a way to EARN a strong binding; it does not add a second way to issue.
 *
 * Why `start` is operator-guarded and `callback` is not: the callback is reached by the
 * provider redirecting the resident's browser, which cannot carry an operator credential. It
 * is protected instead by `state` — generated server-side, unguessable, and consumed by a
 * single atomic delete — so a caller cannot complete a flow they did not start, and cannot
 * replay one that already finished.
 */
@Controller('enrolment/upstream')
export class UpstreamController {
  constructor(private platform: PlatformService) {}

  private client() {
    const client = this.platform.getUpstreamOidc();
    if (!client) {
      // 503 rather than 404: the route exists, the deployment has simply not declared an
      // upstream provider. Saying so plainly is what stops an integrator concluding the
      // feature is missing from the build.
      throw new ServiceUnavailableException(
        'This deployment has no upstreamOidc provider configured',
      );
    }
    return client;
  }

  /**
   * Begin a sign-in at the external provider.
   *
   * `registrar`-guarded, like issuance itself: this is the first step of enrolling somebody,
   * and an unauthenticated caller able to start flows could drive authorization requests at
   * the jurisdiction's provider on its behalf.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('registrar')
  @Post('start')
  async start(@Req() req: RequestWithOperator, @Body() _body: unknown) {
    const operator = requireOperator(req);
    const { authorizationUrl, state } = await this.client().beginLogin();
    await this.platform.getAudit().record({
      action: 'sso.upstream.start',
      actor: operatorActor(operator),
      outcome: 'success',
      metadata: { state },
    });
    return { authorizationUrl, state };
  }

  /**
   * The provider's redirect lands here.
   *
   * Returns the identity and the binding rather than issuing anything. Enrolment stays one
   * decision made in one place (`POST /residency/issue`, registrar-guarded), and folding
   * issuance into an endpoint the provider redirects into would mean a residency could be
   * created by a request no operator ever made.
   */
  @Get('callback')
  async callback(
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('error') error?: string,
  ) {
    // `state` is required on every path, including the error redirect: RFC 6749 s4.1.2.1
    // says a conformant OP echoes it there too, and without it this unguarded route would
    // accept an anonymous ?error=<text> and write it to the hash-chained audit log.
    if (!state || (!error && !code)) {
      throw new BadRequestException('callback needs state, plus either code or error');
    }
    const result = await this.client().completeLogin({ code, state, error });

    await this.platform.getAudit().record({
      action: 'sso.upstream.callback',
      // No operator: the resident's browser arrives here, and attributing it to staff who
      // are not present would put a name in the trail that did not act.
      actor: 'citizen',
      outcome: result.authenticated ? 'success' : 'failure',
      metadata: { acr: result.acr, reason: result.reason },
    });

    if (!result.authenticated) {
      return { authenticated: false, reason: result.reason };
    }
    return {
      authenticated: true,
      // The upstream subject, already tokenized under the deployment pepper by the client.
      // The provider's own identifier never reaches a caller here.
      identity: result.identity,
      acr: result.acr,
      assurance: result.assurance,
      // Hand this to POST /residency/issue as `binding`.
      binding: result.binding,
    };
  }
}
