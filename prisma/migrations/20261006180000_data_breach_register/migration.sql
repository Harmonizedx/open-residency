-- CreateTable: the breach register (additive under ORRA §15).
CREATE TABLE "DataBreach" (
    "id" TEXT NOT NULL,
    "countryCode" TEXT NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL,
    "recordedAt" TIMESTAMP(3) NOT NULL,
    "recordedBy" TEXT NOT NULL,
    "categories" TEXT[],
    "description" TEXT NOT NULL,
    "subjectsAffected" INTEGER,
    "highRisk" BOOLEAN NOT NULL,
    "containment" TEXT,
    "notifyAuthorityBy" TIMESTAMP(3) NOT NULL,
    "notifySubjects" TEXT NOT NULL,
    "authorityNotifiedAt" TIMESTAMP(3),
    "subjectsNotifiedAt" TIMESTAMP(3),
    "amends" TEXT,

    CONSTRAINT "DataBreach_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DataBreach_countryCode_recordedAt_idx" ON "DataBreach"("countryCode", "recordedAt");
