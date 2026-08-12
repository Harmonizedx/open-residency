// SPDX-License-Identifier: Apache-2.0
import { IsArray, IsBoolean, IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';

// Fields are kept optional (not required) so the controller's own presence checks and their
// specific error messages ("email and password are required") still drive the responses; the
// DTOs constrain shape and length and reject unknown properties.

/** `POST /operator/login`. */
export class OperatorLoginDto {
  @IsOptional() @IsString() @MaxLength(256) email?: string;
  @IsOptional() @IsString() @MaxLength(256) password?: string;
  @IsOptional() @IsString() @MaxLength(16) totp?: string;
}

/** `POST /operator/operators`. Roles are shape-checked here; the controller filters them to valid `OperatorRole`s. */
export class CreateOperatorDto {
  @IsOptional() @IsString() @MaxLength(256) email?: string;
  @IsOptional() @IsString() @MaxLength(128) displayName?: string;
  @IsOptional() @IsArray() @IsString({ each: true }) roles?: string[];
  @IsOptional() @IsString() @MaxLength(256) password?: string;
}

/** `POST /operator/operators/:id/disable`. */
export class DisableOperatorDto {
  @IsOptional() @IsString() @MaxLength(64) operatorId?: string;
  @IsOptional() @IsBoolean() disabled?: boolean;
}

/** `POST /operator/keys`. */
export class CreateKeyDto {
  @IsOptional() @IsString() @MaxLength(128) label?: string;
  @IsOptional() @IsInt() @Min(1) @Max(3650) expiresInDays?: number;
}

/** `POST /operator/keys/rotate`. */
export class RotateKeyDto {
  @IsOptional() @IsString() @MaxLength(64) keyId?: string;
  @IsOptional() @IsInt() @Min(1) @Max(720) overlapHours?: number;
}

/** `POST /operator/keys/revoke`. */
export class RevokeKeyDto {
  @IsOptional() @IsString() @MaxLength(64) keyId?: string;
}
