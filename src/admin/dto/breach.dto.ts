// SPDX-License-Identifier: Apache-2.0
import { ArrayMinSize, IsArray, IsBoolean, IsIn, IsInt, IsOptional, IsString, Matches, MaxLength, Min } from 'class-validator';

const ISO = /^\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?$/;

/** Body for `POST /admin/compliance/breaches`. Describes an incident; never names the people affected. */
export class RecordBreachDto {
  @IsString()
  @Matches(/^[A-Za-z]{2}$/)
  countryCode!: string;

  /** When the controller became aware. The 72-hour clock runs from here. */
  @IsString()
  @Matches(ISO, { message: 'detectedAt must be an ISO 8601 date or instant' })
  detectedAt!: string;

  @IsArray()
  @ArrayMinSize(1)
  @IsIn(['confidentiality', 'integrity', 'availability'], { each: true })
  categories!: Array<'confidentiality' | 'integrity' | 'availability'>;

  @IsString()
  @MaxLength(4000)
  description!: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  subjectsAffected?: number;

  @IsBoolean()
  highRisk!: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(4000)
  containment?: string;

  @IsOptional()
  @IsString()
  @Matches(ISO)
  authorityNotifiedAt?: string;

  @IsOptional()
  @IsString()
  @Matches(ISO)
  subjectsNotifiedAt?: string;

  /** An earlier entry this one amends or closes. */
  @IsOptional()
  @IsString()
  @MaxLength(64)
  amends?: string;
}
