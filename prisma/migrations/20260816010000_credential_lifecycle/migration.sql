-- AlterTable
ALTER TABLE "Resident" ADD COLUMN     "appealPath" TEXT,
ADD COLUMN     "credentialAuthority" TEXT,
ADD COLUMN     "credentialReason" TEXT,
ADD COLUMN     "credentialStatus" TEXT NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN     "credentialStatusAt" TIMESTAMP(3),
ADD COLUMN     "supersededBy" TEXT;

-- AlterTable
ALTER TABLE "StatusListState" DROP CONSTRAINT "StatusListState_pkey",
ADD COLUMN     "purpose" TEXT NOT NULL DEFAULT 'revocation',
ADD CONSTRAINT "StatusListState_pkey" PRIMARY KEY ("countryCode", "purpose");

