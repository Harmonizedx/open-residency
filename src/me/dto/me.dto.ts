// SPDX-License-Identifier: Apache-2.0
import { IsOptional, IsString, MaxLength } from 'class-validator';

/** Body for `POST /me/access-log/start`: which record, so a code can go to its registered contact. */
export class AccessLogStartDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  residentId?: string;
}

/** Body for `POST /me/access-log`: the record and the code that was sent to its contact. */
export class AccessLogDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  residentId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(16)
  code?: string;
}
