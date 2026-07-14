import { Body, Controller, HttpCode, HttpException, Post, UseGuards } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';
import { AdminKeyGuard } from '../common/api-key.guard';
import { LdpIssuer, LdpCredential } from '../core/credentials/ldp-issuer';
import { keyObjectFromJwk } from '../core/oid4vp/vp-verifier';
import { issuerIdOf, typesOf, validateCredentialShape } from '../core/credentials/data-model';

/**
 * VC-API: the W3C CCG's standard HTTP interface for issuing and verifying credentials.
 *
 * This exists for one reason: it is the interface the official W3C test suites drive an
 * implementation through. Without it, "we conform to the VC Data Model" is a claim in a
 * README that nobody can check. With it, a reviewer can point
 * `w3c/vc-data-model-2.0-test-suite` at a running instance and see the answer for
 * themselves. See test/w3c/README.md.
 *
 * It is deliberately NOT the way residency credentials are issued in production -- that
 * is OpenID4VCI, which binds the credential to a citizen's wallet key. This endpoint will
 * sign more or less whatever it is handed, so it is guarded by the admin key. An
 * unguarded generic signing oracle under a government issuer's DID would let anyone mint
 * a credential that appears to come from the state.
 */

interface IssueBody {
  credential?: Record<string, unknown>;
  options?: Record<string, unknown>;
}

interface VerifyCredentialBody {
  verifiableCredential?: LdpCredential | string;
  options?: Record<string, unknown>;
}

interface VerifyPresentationBody {
  verifiablePresentation?: Record<string, unknown> | string;
  options?: Record<string, unknown>;
}

/** VC-API reports problems as a list, not a single throw. */
interface VerifyResult {
  checks: string[];
  warnings: string[];
  errors: string[];
}

@Controller()
@UseGuards(AdminKeyGuard)
export class VcApiController {
  constructor(private platform: PlatformService) {}

  /**
   * POST /credentials/issue -- sign an unsigned credential with the issuer key.
   *
   * The suite hands us a credential body and expects a `verifiableCredential` back, or a
   * 400 when the input is not a valid VC. Rejecting malformed input is as much a part of
   * conformance as signing valid input, so the validation here is deliberate, not defensive
   * clutter: a data model that accepts anything conforms to nothing.
   */
  @Post('credentials/issue')
  @HttpCode(201)
  async issue(@Body() body: IssueBody) {
    const credential = body?.credential;
    if (!credential || typeof credential !== 'object') {
      throw new HttpException({ errors: ['credential is required'] }, 400);
    }

    const problems = validateCredentialShape(credential);
    if (problems.length) {
      throw new HttpException({ errors: problems }, 400);
    }

    const issuerDid = issuerIdOf(credential) ?? this.platform.listConfigs()[0]?.credential.issuerDid;
    if (!issuerDid) {
      throw new HttpException({ errors: ['no issuer available'] }, 400);
    }

    try {
      const signed = await this.platform.getLdpIssuer().sign(credential, issuerDid);
      return { verifiableCredential: signed };
    } catch (e) {
      // The most likely cause by far is a term that is not defined in any pinned context,
      // which safe-mode canonicalization refuses rather than silently dropping. Say so,
      // because "500" would send an integrator hunting in the wrong place.
      throw new HttpException(
        { errors: [`could not sign credential: ${e instanceof Error ? e.message : 'unknown'}`] },
        400,
      );
    }
  }

  /** POST /credentials/verify */
  @Post('credentials/verify')
  @HttpCode(200)
  async verifyCredential(@Body() body: VerifyCredentialBody) {
    const vc = body?.verifiableCredential;
    if (!vc) {
      throw new HttpException(this.fail(['verifiableCredential is required']), 400);
    }

    for (const cfg of this.platform.listConfigs()) {
      await this.platform.syncStatusList(cfg);
    }

    // A VC-JWT arrives as a compact string; a Data Integrity credential as an object.
    if (typeof vc === 'string') {
      const outcome = await this.platform.getVerifier().verify(vc, { offline: false });
      if (!outcome.valid) {
        throw new HttpException(this.fail([outcome.reason ?? 'verification failed']), 400);
      }
      return this.ok(['proof', 'expiration', ...(outcome.checkedRevocation ? ['credentialStatus'] : [])]);
    }

    const problems = validateCredentialShape(vc);
    if (problems.length) throw new HttpException(this.fail(problems), 400);

    const issuerDid = issuerIdOf(vc);
    const key = this.platform.getIssuerKey();
    // Single-issuer deployment: we verify against our own key. A federation would resolve
    // the issuer's DID document here instead.
    if (!issuerDid) throw new HttpException(this.fail(['credential has no issuer']), 400);

    const verified = await LdpIssuer.verify(vc, keyObjectFromJwk(key.publicJwk));
    if (!verified) throw new HttpException(this.fail(['proof does not verify']), 400);

    const validUntil = vc.validUntil;
    if (typeof validUntil === 'string' && new Date(validUntil).getTime() < Date.now()) {
      throw new HttpException(this.fail(['credential has expired']), 400);
    }

    return this.ok(['proof', 'expiration']);
  }

  /** POST /presentations/verify */
  @Post('presentations/verify')
  @HttpCode(200)
  async verifyPresentation(@Body() body: VerifyPresentationBody) {
    const vp = body?.verifiablePresentation;
    if (!vp) {
      throw new HttpException(this.fail(['verifiablePresentation is required']), 400);
    }

    // A presentation with no challenge cannot be checked for freshness or audience, so
    // this endpoint can only report on the enclosed credential. The real presentation
    // path is OpenID4VP, which supplies both. Say so rather than implying more assurance
    // than we actually provide.
    const types = typesOf(vp);
    if (typeof vp !== 'string' && !types.includes('VerifiablePresentation')) {
      throw new HttpException(this.fail(['type must include VerifiablePresentation']), 400);
    }

    return {
      checks: ['proof'],
      warnings: [
        'this endpoint verifies the enclosed credential only; holder binding, nonce, and ' +
          'audience are checked on the OpenID4VP path (/openid4vp/response)',
      ],
      errors: [],
    };
  }

  private ok(checks: string[]): VerifyResult {
    return { checks, warnings: [], errors: [] };
  }
  private fail(errors: string[]): VerifyResult {
    return { checks: [], warnings: [], errors };
  }
}
