// SPDX-License-Identifier: Apache-2.0
import {
  ArrayMaxSize,
  IsArray,
  IsIn,
  IsISO8601,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

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
  @ArrayMaxSize(50)
  @IsString({ each: true })
  @MaxLength(128, { each: true })
  scopes!: string[];

  @IsOptional()
  @IsInt()
  @Min(1)
  validityDays?: number;

  // ---- ORCS §9 -------------------------------------------------------------
  //
  // Required, not optional. An optional accountability field is one that arrives empty, and
  // the service refuses the grant anyway -- so accepting the request and failing later would
  // only move the error further from the caller who can fix it.

  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  @MaxLength(128, { each: true })
  dataCategories!: string[];

  @IsIn(['sso_consent_screen', 'operator_recorded', 'signed_form', 'ussd_confirmation', 'imported_record'])
  evidenceMethod!: string;

  /** Where the agreement itself is retained: a form id, document or transaction reference. */
  @IsString()
  @MaxLength(256)
  evidenceReference!: string;

  @IsOptional()
  @IsISO8601()
  evidenceAt?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  evidenceCapturedBy?: string;

  /** Must resolve through the Legal Basis Registry. Defaults to the deployment's basis. */
  @IsOptional()
  @IsString()
  @MaxLength(256)
  legalBasisReference?: string;
}

/** Request body for `POST /legal-bases/:id/deactivate`. */
export class DeactivateLegalBasisDto {
  @IsString()
  @MaxLength(512)
  reason!: string;

  @IsString()
  @MaxLength(256)
  authority!: string;
}
