-- AlterTable
ALTER TABLE "Resident" ADD COLUMN     "assuranceProfileId" TEXT,
ADD COLUMN     "decidedAt" TIMESTAMP(3),
ADD COLUMN     "decidedBy" TEXT,
ADD COLUMN     "endedAt" TIMESTAMP(3),
ADD COLUMN     "endedBy" TEXT,
ADD COLUMN     "endedReason" TEXT,
ADD COLUMN     "evidenceRefs" TEXT[],
ADD COLUMN     "policyVersion" TEXT,
ADD COLUMN     "relationshipIssuer" TEXT,
ADD COLUMN     "relationshipPurpose" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "relationshipStatus" TEXT NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN     "relationshipType" TEXT NOT NULL DEFAULT 'GENERAL_RESIDENCY',
ADD COLUMN     "validFrom" TIMESTAMP(3),
ADD COLUMN     "validTo" TIMESTAMP(3);

