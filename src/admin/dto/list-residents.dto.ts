import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Matches, Max, Min } from 'class-validator';

/**
 * Query params for `GET /admin/residents`.
 *
 * `limit`/`offset` arrive as strings and were previously `Number(...)`-ed straight into the
 * Prisma `take:` with no bounds. `@Type(() => Number)` coerces them and `@Min/@Max` bound
 * them, so a caller cannot request an unbounded (or negative) page.
 */
export class ListResidentsQueryDto {
  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-z]{2}$/, { message: 'countryCode must be a 2-letter code' })
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
