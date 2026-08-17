-- ORCS §9: consent records carry the controller, processor, data categories, evidence of
-- agreement and a legal basis that resolves through the registry.
--
-- Additive, per ORRA §15. Existing rows keep working: the new text columns default to '' and
-- the version to 1, so a row written before this migration reads as an unversioned grant with
-- no accountability fields recorded -- which is exactly what it was. Backfilling them with a
-- guess would assert a controller and a lawful basis nobody actually decided.
ALTER TABLE "ConsentRecord" ADD COLUMN "controller" TEXT NOT NULL DEFAULT '';
ALTER TABLE "ConsentRecord" ADD COLUMN "processor" TEXT;
ALTER TABLE "ConsentRecord" ADD COLUMN "dataCategories" TEXT[];
ALTER TABLE "ConsentRecord" ADD COLUMN "legalBasisReference" TEXT NOT NULL DEFAULT '';
ALTER TABLE "ConsentRecord" ADD COLUMN "evidenceMethod" TEXT NOT NULL DEFAULT '';
ALTER TABLE "ConsentRecord" ADD COLUMN "evidenceAt" TIMESTAMP(3);
ALTER TABLE "ConsentRecord" ADD COLUMN "evidenceReference" TEXT NOT NULL DEFAULT '';
ALTER TABLE "ConsentRecord" ADD COLUMN "evidenceCapturedBy" TEXT;
ALTER TABLE "ConsentRecord" ADD COLUMN "version" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "ConsentRecord" ADD COLUMN "supersedesId" TEXT;
ALTER TABLE "ConsentRecord" ADD COLUMN "supersededById" TEXT;
ALTER TABLE "ConsentRecord" ADD COLUMN "withdrawnBy" TEXT;

-- CreateTable
CREATE TABLE "LegalBasis" (
    "id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "instrument" TEXT NOT NULL,
    "jurisdiction" TEXT NOT NULL,
    "controller" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "effectiveFrom" TIMESTAMP(3) NOT NULL,
    "effectiveTo" TIMESTAMP(3),
    "deactivatedAt" TIMESTAMP(3),
    "deactivationReason" TEXT,
    "deactivatedBy" TEXT,

    CONSTRAINT "LegalBasis_pkey" PRIMARY KEY ("id")
);