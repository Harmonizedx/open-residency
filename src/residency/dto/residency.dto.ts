// SPDX-License-Identifier: Apache-2.0
import { Allow, IsBoolean, IsIn, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { IsStringRecord } from '../../common/dto/is-string-record.validator';
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

  @IsStringRecord()
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

/**
 * Request body for `POST /residency/{residentId}/relationship/transition`.
 *
 * `status` is a closed set rather than a free string: ORCS §6.2 defines the vocabulary, and a
 * typo landing an unrecognised state on a record would be indistinguishable from a real one.
 * The states omitted here (DRAFT, SUBMITTED, EVIDENCE_PENDING, UNDER_REVIEW, REJECTED)
 * describe a submission workflow a single-jurisdiction deployment does not have.
 *
 * `reason` is required by the engine for any terminal transition, not by this DTO -- the rule
 * belongs with the transition logic, which is also what an internal caller goes through.
 */
export class TransitionRelationshipDto {
  @IsIn(['ACTIVE', 'SUSPENDED', 'ENDED', 'REVOKED', 'EXPIRED'])
  status!: 'ACTIVE' | 'SUSPENDED' | 'ENDED' | 'REVOKED' | 'EXPIRED';

  @IsOptional()
  @IsString()
  @MaxLength(512)
  reason?: string;
}

/**
 * Request body for `POST /residency/{residentId}/credential/transition`.
 *
 * ORCS §10 requires a revocation to preserve reason, authority, timestamp and appeal path.
 * Authority and timestamp come from the authenticated operator context and the clock, so what
 * a caller supplies is the reason and — for a revocation — the appeal path. The engine refuses
 * a terminal transition missing either, rather than writing a blank.
 */
export class CredentialTransitionDto {
  @IsIn(['ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED', 'REPLACED'])
  status!: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED' | 'REPLACED';

  @IsOptional()
  @IsString()
  @MaxLength(512)
  reason?: string;

  /** Overrides the jurisdiction's configured appeal path for this decision. */
  @IsOptional()
  @IsString()
  @MaxLength(512)
  appealPath?: string;

  /** The credential that replaces this one. Required for REPLACED (ORCS §10). */
  @IsOptional()
  @IsString()
  @MaxLength(512)
  supersededBy?: string;
}

/**
 * Request body for `POST /residency/:residentId/reconcile`.
 *
 * Only the identifiers: everything else about the record is already held, and re-accepting
 * it here would let a caller quietly amend a residency under cover of confirming one. The
 * identifiers must be resubmitted because the raw national id is never stored -- the
 * register keeps only the tokenized subjectRef the live lookup is checked against.
 */
export class ReconcileDto {
  @IsStringRecord()
  identifiers!: Record<string, string>;
}

/**
 * Request body for `POST /residency/refusals/{reference}/review`.
 *
 * `overturned` is a real option, not a courtesy. NDPA 2023 s.37, GDPR Art.22 and Convention
 * 108+ all require the reviewer to hold genuine authority to reach a different outcome, so an
 * endpoint that could only ever record "a human looked" would satisfy the letter and miss the
 * point entirely.
 */
export class RecordReviewDto {
  @IsIn(['requested', 'upheld', 'overturned'])
  status!: 'requested' | 'upheld' | 'overturned';

  @IsOptional()
  @IsString()
  @MaxLength(1024)
  note?: string;
}
