-- CreateTable: credential delivery events (additive under ORRA §15).
CREATE TABLE "CredentialDelivery" (
    "id" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "countryCode" TEXT NOT NULL,
    "credentialId" TEXT,
    "channel" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "by" TEXT,
    "failureReason" TEXT,
    "evidenceRef" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CredentialDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CredentialDelivery_residentId_at_idx" ON "CredentialDelivery"("residentId", "at");

-- CreateIndex
CREATE INDEX "CredentialDelivery_countryCode_channel_status_idx" ON "CredentialDelivery"("countryCode", "channel", "status");
