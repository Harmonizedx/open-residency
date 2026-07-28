import { IsOptional, IsString, MaxLength } from 'class-validator';

/**
 * Body for the residentId-only auth-start endpoints (`otp/start`,
 * `webauthn/authenticate/start`).
 *
 * `residentId` is deliberately OPTIONAL: these endpoints answer identically whether or not
 * a residency id was supplied or exists (residency ids are semi-public), so requiring it and
 * returning a 400 on absence would leak that a well-formed id was expected. Shape and length
 * are still constrained, and unknown properties are rejected.
 */
export class AuthStartDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  residentId?: string;
}

/** Body for `otp/verify`. Both fields optional so the controller keeps its own MISSING_FIELDS handling. */
export class OtpVerifyDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  residentId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(16)
  code?: string;
}
