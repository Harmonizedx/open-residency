import { Controller, Get, NotFoundException, Param } from '@nestjs/common';
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

  /** Published revocation list as a signed-list-ready JSON, e.g. /.well-known/status/ng.json */
  @Get('status/:file')
  async status(@Param('file') file: string) {
    const countryCode = file.replace(/\.json$/i, '');
    const cfg = this.platform.getConfig(countryCode);
    if (!cfg) throw new NotFoundException('Unknown country');
    const list = await this.platform.getStore().loadStatusList(cfg.countryCode);
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: this.platform.statusListUrl(cfg),
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: cfg.credential.issuerDid,
      validFrom: new Date().toISOString(),
      credentialSubject: list.toCredentialSubject(this.platform.statusListUrl(cfg)),
    };
  }
}
