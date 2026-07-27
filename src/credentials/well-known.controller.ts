import { Controller, Get, Header, NotFoundException, Param } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';

/**
 * Publishes the artifacts an offline verifier syncs while online:
 *   - the issuer DID document (public key), and
 *   - the revocation status list per country.
 * Once cached, verification works with no further network access.
 */
@Controller('.well-known')
export class WellKnownController {
  constructor(private platform: PlatformService) {}

  /** did:web resolution endpoint, e.g. GET /.well-known/did.json?country=NG */
  @Get('did.json')
  didJson() {
    // Single-tenant deployments serve one issuer DID document.
    const first = this.platform.listConfigs()[0];
    if (!first) throw new NotFoundException();
    return this.platform.didDocument(first.countryCode);
  }

  @Get('did/:countryCode.json')
  didForCountry(@Param('countryCode') countryCode: string) {
    const doc = this.platform.didDocument(countryCode);
    if (!doc) throw new NotFoundException('Unknown country');
    return doc;
  }

  /**
   * Published revocation list as a SIGNED BitstringStatusListCredential,
   * e.g. /.well-known/status/ng.json (#27).
   *
   * The list is signed with the issuer key, not served as bare JSON. A verifier syncs this
   * snapshot and checks revocation offline against it, so the cached artifact itself must be
   * self-authenticating -- TLS only protects it in flight, not at rest in the verifier's
   * cache. The DID document already publishes the Multikey this proof's verificationMethod
   * names, so no new trust material is introduced.
   *
   * Signing is cached by the publisher and only re-run when the list content changes, so
   * this public, unauthenticated endpoint never re-invokes the issuer key (HSM/KMS) on a
   * plain poll. The Cache-Control header lets verifiers and any CDN cache the snapshot too.
   */
  @Get('status/:file')
  @Header('Cache-Control', 'public, max-age=300')
  async status(@Param('file') file: string) {
    const countryCode = file.replace(/\.json$/i, '');
    const cfg = this.platform.getConfig(countryCode);
    if (!cfg) throw new NotFoundException('Unknown country');
    const list = await this.platform.getStore().loadStatusList(cfg.countryCode);
    return this.platform
      .getStatusListPublisher()
      .publish(this.platform.statusListUrl(cfg), cfg.credential.issuerDid, list);
  }
}
