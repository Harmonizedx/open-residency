import { IsOptional, IsString, MaxLength } from 'class-validator';

/**
 * Request body for `POST /oid4vp/request` (our own "start a presentation" call).
 *
 * The presentation RESPONSE endpoint (`POST /oid4vp/response/:id`) carries a spec-shaped
 * `vp_token` and is deliberately left pass-through — its payload is defined by OpenID4VP,
 * not by us, and is validated by the VP verifier.
 */
export class CreatePresentationRequestDto {
  @IsOptional()
  @IsString()
  @MaxLength(512)
  purpose?: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  reference?: string;
}
