import { IsArray, IsInt, IsOptional, IsString, MaxLength, Min } from 'class-validator';

/** Request body for `POST /consent/grant`. */
export class GrantConsentDto {
  @IsString()
  @MaxLength(128)
  residentId!: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  subjectRef?: string;

  @IsString()
  @MaxLength(128)
  relyingParty!: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  relyingPartyName?: string;

  @IsString()
  @MaxLength(512)
  purpose!: string;

  @IsArray()
  @IsString({ each: true })
  scopes!: string[];

  @IsOptional()
  @IsInt()
  @Min(1)
  validityDays?: number;
}
