// SPDX-License-Identifier: Apache-2.0
import { Type } from 'class-transformer';
import { IsIn, IsInt, IsISO8601, IsOptional, IsString, Matches, Max, MaxLength, Min } from 'class-validator';
import {
  ARRIVAL_NOTICE_RESOLUTIONS,
  ARRIVAL_NOTICE_STATUSES,
  ArrivalNoticeDirection,
  ArrivalNoticeResolution,
  ArrivalNoticeStatus,
} from '../../core/residency/arrival-notice';

/** Body of `POST /federation/arrival-notices`: a peer's signed notice, as a compact JWT. */
export class ReceiveArrivalNoticeDto {
  @IsString()
  @Matches(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  @MaxLength(8192)
  notice!: string;
}

/**
 * Body of `POST /federation/arrival-notices/outbound`: the credential a mover presented at
 * this deployment's desk, after being registered here. The issuer is read from the
 * credential, never from the body, and the credential is verified before anything is sent.
 */
export class SendArrivalNoticeDto {
  @IsString()
  @Matches(/^[A-Za-z]{2}$/)
  countryCode!: string;

  @IsString()
  @Matches(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  @MaxLength(16384)
  credential!: string;

  @IsOptional()
  @IsISO8601()
  presentedAt?: string;

  @IsOptional()
  @IsISO8601()
  registeredAt?: string;
}

/** Body of `POST /federation/arrival-notices/{id}/resolve`: a person's decision, with its reason. */
export class ResolveArrivalNoticeDto {
  @IsIn(ARRIVAL_NOTICE_RESOLUTIONS as readonly string[])
  resolution!: ArrivalNoticeResolution;

  @IsString()
  @MaxLength(512)
  reason!: string;
}

export class ListArrivalNoticesQueryDto {
  @IsOptional()
  @IsIn(['inbound', 'outbound'])
  direction?: ArrivalNoticeDirection;

  @IsOptional()
  @IsIn(ARRIVAL_NOTICE_STATUSES as readonly string[])
  status?: ArrivalNoticeStatus;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  residentId?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-z]{2}$/)
  countryCode?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(500)
  limit?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  offset?: number;
}
