-- AlterTable
ALTER TABLE "Resident" ADD COLUMN     "submittedBy" TEXT;

-- AlterTable
ALTER TABLE "ResidencyRefusal" ADD COLUMN     "humanReviewPath" TEXT,
ADD COLUMN     "reviewNote" TEXT,
ADD COLUMN     "reviewStatus" TEXT NOT NULL DEFAULT 'none',
ADD COLUMN     "reviewedAt" TIMESTAMP(3),
ADD COLUMN     "reviewedBy" TEXT,
ADD COLUMN     "submittedBy" TEXT;

