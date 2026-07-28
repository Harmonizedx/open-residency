import { IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { IsStringRecord } from '../../common/dto/is-string-record.validator';

/** Request body for `POST /identity/challenge`. */
export class ChallengeDto {
  @IsString()
  @Matches(/^[A-Za-z]{2}$/, { message: 'countryCode must be a 2-letter code' })
  countryCode!: string;

  @IsStringRecord()
  identifiers!: Record<string, string>;
}

/** Request body for `POST /identity/verify` (challenge fields plus an optional purpose). */
export class VerifyIdentityDto extends ChallengeDto {
  @IsOptional()
  @IsString()
  @MaxLength(256)
  challengeRef?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  purpose?: string;
}
