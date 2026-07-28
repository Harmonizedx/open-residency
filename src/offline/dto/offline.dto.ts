import { IsOptional, IsString, MaxLength } from 'class-validator';

/** Request body for `POST /offline/qr` — render a credential as a QR. */
export class QrDto {
  @IsString()
  @MaxLength(16384)
  credential!: string;

  @IsString()
  @MaxLength(128)
  residentId!: string;
}

/**
 * Request body for the USSD gateway webhook `POST /offline/ussd`.
 * Gateway-guarded; the aggregator sends `sessionId`, `phoneNumber`, and the menu `text`.
 */
export class UssdDto {
  @IsOptional()
  @IsString()
  @MaxLength(128)
  sessionId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  phoneNumber?: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  text?: string;
}
