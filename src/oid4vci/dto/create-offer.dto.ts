// SPDX-License-Identifier: Apache-2.0
import { IsOptional, IsString, MaxLength } from 'class-validator';

/**
 * Request body for `POST /oid4vci/offer` (operator-initiated credential offer).
 *
 * The OID4VCI protocol endpoints on this controller — `POST /oid4vci/token` and
 * `POST /oid4vci/credential` — are deliberately left pass-through: their bodies are defined
 * by OAuth 2.0 / OpenID4VCI (extensible, with hyphenated keys like `pre-authorized_code`),
 * so a whitelist would reject spec-legal fields and break wallet interop. They are typed as
 * `Record<...>` and validated by the OID4VCI service instead.
 */
export class CreateOfferDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  residentId?: string;
}
