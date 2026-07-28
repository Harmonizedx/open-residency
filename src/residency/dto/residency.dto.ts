import { Allow, IsBoolean, IsObject, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { ApplicantBinding } from '../../core/proofing/binding';
import { ResidenceEvidence } from '../../core/proofing/residence';

/**
 * Request body for `POST /residency/issue`.
 *
 * Every field the controller reads is declared here: with the global ValidationPipe running
 * `forbidNonWhitelisted`, an undeclared property is rejected rather than silently passed on.
 * The scalars an attacker controls are constrained tightly -- `subnationalUnit` above all,
 * since it is persisted, asserted into the credential, and rendered in the admin console
 * (engine-side validation is the second line of defence, this is the first).
 *
 * `binding` and `residenceEvidence` are only whitelisted here (`@Allow`) and validated
 * semantically by the core engine (`ResidencyService`), so the DTO layer does not have to
 * import the core's validation rules -- keeping the core/delivery boundary intact.
 */
export class IssueDto {
  @IsString()
  @Matches(/^[A-Za-z]{2}$/, { message: 'countryCode must be a 2-letter code' })
  countryCode!: string;

  @IsString()
  @Matches(/^[A-Za-z0-9_-]{1,32}$/, { message: 'subnationalUnit must be 1-32 chars of [A-Za-z0-9_-]' })
  subnationalUnit!: string;

  @IsObject()
  identifiers!: Record<string, string>;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  holderId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  challengeRef?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  proofOfResidence?: string;

  @IsOptional()
  @Allow()
  binding?: ApplicantBinding;

  @IsOptional()
  @Allow()
  residenceEvidence?: ResidenceEvidence[];

  @IsOptional()
  @IsString()
  @Matches(/^\+?[0-9]{6,20}$/, { message: 'phone must be digits, optionally +-prefixed' })
  phone?: string;

  @IsOptional()
  @IsBoolean()
  offline?: boolean;
}

/** Request body for `POST /residency/verify` (public credential check). */
export class VerifyDto {
  @IsString()
  @MaxLength(16384)
  credential!: string;

  @IsOptional()
  @IsBoolean()
  offline?: boolean;
}
