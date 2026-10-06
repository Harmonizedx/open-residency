-- AlterTable: the residence rule's inputs, all nullable (additive under ORRA §15).
ALTER TABLE "Resident" ADD COLUMN     "residenceSince" TIMESTAMP(3),
ADD COLUMN     "residenceMode" TEXT,
ADD COLUMN     "residenceAttesterType" TEXT,
ADD COLUMN     "residenceIntent" BOOLEAN;
