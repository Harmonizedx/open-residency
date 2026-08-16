-- CreateTable
CREATE TABLE "ResidencyRefusal" (
    "reference" TEXT NOT NULL,
    "countryCode" TEXT NOT NULL,
    "subnationalUnit" TEXT NOT NULL,
    "subjectRef" TEXT,
    "reason" TEXT NOT NULL,
    "decidedBy" TEXT NOT NULL,
    "appealPath" TEXT NOT NULL,
    "refusedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ResidencyRefusal_pkey" PRIMARY KEY ("reference")
);

-- CreateIndex
CREATE INDEX "ResidencyRefusal_subjectRef_idx" ON "ResidencyRefusal"("subjectRef");

-- CreateIndex
CREATE INDEX "ResidencyRefusal_countryCode_refusedAt_idx" ON "ResidencyRefusal"("countryCode", "refusedAt");

