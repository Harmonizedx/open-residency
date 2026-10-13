-- Arrival notices between federated jurisdictions (additive under ORRA §15; ADR-0018).
CREATE TABLE "ArrivalNotice" (
    "id" TEXT NOT NULL,
    "direction" TEXT NOT NULL,
    "peerDid" TEXT NOT NULL,
    "peerName" TEXT,
    "credentialId" TEXT NOT NULL,
    "presentationHash" TEXT NOT NULL,
    "presentedAt" TIMESTAMP(3) NOT NULL,
    "registeredAt" TIMESTAMP(3) NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "residentId" TEXT,
    "countryCode" TEXT,
    "rule" TEXT,
    "graceDays" INTEGER,
    "effectiveAt" TIMESTAMP(3),
    "status" TEXT NOT NULL,
    "conflict" BOOLEAN NOT NULL DEFAULT false,
    "appliedAt" TIMESTAMP(3),
    "appliedTransition" TEXT,
    "applyFailure" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "resolvedBy" TEXT,
    "resolution" TEXT,
    "resolutionReason" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastAttemptAt" TIMESTAMP(3),
    "deliveryDetail" TEXT,
    "notice" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArrivalNotice_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArrivalNotice_residentId_at_idx" ON "ArrivalNotice"("residentId", "at");

-- CreateIndex
CREATE INDEX "ArrivalNotice_direction_status_effectiveAt_idx" ON "ArrivalNotice"("direction", "status", "effectiveAt");

-- CreateIndex
CREATE INDEX "ArrivalNotice_credentialId_idx" ON "ArrivalNotice"("credentialId");

-- An inbound notice names a credential id and nothing else, so the record is found by it.
CREATE INDEX "Resident_credentialId_idx" ON "Resident"("credentialId");
