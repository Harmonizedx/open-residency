// SPDX-License-Identifier: Apache-2.0
import { Controller, Get, NotFoundException, Param } from '@nestjs/common';
import { PlatformService } from '../platform/platform.service';

/**
 * The Assurance Registry as a published surface (ORCS §8).
 *
 * The profiles and provider mappings are deliberately unauthenticated. A governed profile is
 * a published position about what a verification establishes -- a relying party deciding
 * whether to accept a residency credential has to be able to read the mapping *before* it
 * trusts anything, and an authority's published limitations are not a secret. Nothing on
 * these routes concerns an individual.
 */
@Controller('assurance')
export class AssuranceController {
  constructor(private platform: PlatformService) {}

  /** Every canonical profile an assurance value can resolve to (ORCS §8). */
  @Get('profiles')
  profiles() {
    return this.platform.getAssuranceRegistry().listProfiles();
  }

  /** What each identity source publishes about its own verification (ORCS §8.1). */
  @Get('mappings')
  mappings() {
    return this.platform.getAssuranceRegistry().listMappings();
  }

  /**
   * Resolve one declared value, optionally as a named provider means it.
   *
   * A value that does not resolve is a 404 rather than an empty result: "not a governed
   * value" is the answer ORCS §8 wants a caller to receive, and returning a blank record
   * would let a caller treat an ungoverned string as merely uninformative.
   */
  @Get('resolve/:value')
  resolve(@Param('value') value: string) {
    const profile = this.platform.getAssuranceRegistry().resolve(value);
    if (!profile) {
      throw new NotFoundException(
        `"${value}" is not a governed assurance value. ORCS §8 requires every assurance ` +
          'value to resolve to a profile in the Assurance Registry.',
      );
    }
    return profile;
  }
}

/**
 * Resolving a specific resident's assurance. Separate controller only because it hangs off
 * the `residency` path rather than `assurance`.
 *
 * Left unguarded to match the sibling `GET /residency/:residentId`, which is also open and
 * already returns `assuranceLevel` for the same identifier. What this route adds is the
 * governance behind that value -- the profile, the published mapping, the limitations -- all
 * of which are public by design. It releases no attribute about the person that the existing
 * lookup did not. If that lookup is ever placed behind the operator guard, this belongs
 * behind it in the same change, for the same reason.
 */
@Controller('residency')
export class ResidentAssuranceController {
  constructor(private platform: PlatformService) {}

  /**
   * What this resident's recorded assurance actually establishes.
   *
   * This is the end-to-end path ORCS §15 criterion 3 asks for: a stored value, resolved
   * through the governed registry, qualified by what the enrolment itself achieved.
   */
  @Get(':residentId/assurance')
  async residentAssurance(@Param('residentId') residentId: string) {
    // Same shape as the sibling lookup on this path: an unknown id is simply not found.
    // No separate format check, because a format regex here would only distinguish
    // "malformed" from "absent" for an identifier that is semi-public anyway.
    const record = await this.platform.getStore().findByResidentId(residentId);
    if (!record) throw new NotFoundException('Unknown residentId');

    const resolved = this.platform.getAssuranceRegistry().resolveRecord(record);
    if (!resolved) {
      // Reachable only if a record carries a value no profile covers -- a register written
      // before a profile was retired, or a hand-edited row. Reported rather than defaulted.
      throw new NotFoundException(
        `Resident ${residentId} carries assurance value "${record.assuranceLevel}", which ` +
          'does not resolve to a governed profile.',
      );
    }

    return {
      residentId: record.residentId,
      declaredValue: record.assuranceLevel,
      providerCode: record.providerCode,
      profile: resolved.profile,
      mapping: resolved.mapping,
      dimensions: resolved.dimensions,
      limitations: resolved.limitations,
      /**
       * Stated rather than omitted: authentication assurance is not a property of a person.
       * It belongs to a sign-in event and is carried in the id_token `acr` (see
       * core/sso/assurance.ts). ORCS §8 lists them as separate dimensions and this endpoint
       * keeps them separate.
       */
      authenticationAssurance:
        'Not applicable to a stored record. Authentication assurance describes a sign-in ' +
        'event and is issued per session as the OIDC `acr` claim.',
    };
  }
}