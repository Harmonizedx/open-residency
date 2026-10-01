-- ORCS §11: identity links, their event history, and merges. Additive, per ORRA §15: three
-- new tables and no change to Resident. A row written before this migration has no link
-- rows; the residency service backfills the foundational link the first time an operation
-- needs one, from the record's own subjectRef, so nothing here needs a data migration.

-- CreateTable
CREATE TABLE "IdentityLink" (
    "id" TEXT NOT NULL,
    "personRef" TEXT NOT NULL,
    "identifierType" TEXT NOT NULL,
    "identifierRef" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "foundational" BOOLEAN NOT NULL DEFAULT false,
    "evidenceRefs" TEXT[],
    "linkedAt" TIMESTAMP(3) NOT NULL,
    "linkedBy" TEXT NOT NULL,
    "disputeRaisedAt" TIMESTAMP(3),
    "disputeRaisedBy" TEXT,
    "disputeReason" TEXT,
    "disputeResolvedAt" TIMESTAMP(3),
    "disputeResolvedBy" TEXT,
    "disputeResolution" TEXT,
    "unlinkedAt" TIMESTAMP(3),
    "unlinkedBy" TEXT,
    "unlinkedReason" TEXT,
    "unlinkedOperation" TEXT,
    "supersedes" TEXT,
    "supersededBy" TEXT,
    "mergeId" TEXT,

    CONSTRAINT "IdentityLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IdentityLinkEvent" (
    "id" TEXT NOT NULL,
    "seq" SERIAL NOT NULL,
    "linkId" TEXT NOT NULL,
    "personRef" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "by" TEXT NOT NULL,
    "reason" TEXT,
    "evidenceRefs" TEXT[],
    "fromPersonRef" TEXT,
    "toPersonRef" TEXT,
    "mergeId" TEXT,

    CONSTRAINT "IdentityLinkEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IdentityMerge" (
    "id" TEXT NOT NULL,
    "survivorRef" TEXT NOT NULL,
    "duplicateRef" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "by" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "moved" JSONB NOT NULL,
    "splitAt" TIMESTAMP(3),
    "splitBy" TEXT,
    "splitReason" TEXT,
    "splitRestored" JSONB,

    CONSTRAINT "IdentityMerge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IdentityLink_personRef_idx" ON "IdentityLink"("personRef");
CREATE INDEX "IdentityLink_identifierRef_status_idx" ON "IdentityLink"("identifierRef", "status");
CREATE UNIQUE INDEX "IdentityLinkEvent_seq_key" ON "IdentityLinkEvent"("seq");
CREATE INDEX "IdentityLinkEvent_linkId_idx" ON "IdentityLinkEvent"("linkId");
CREATE INDEX "IdentityLinkEvent_personRef_idx" ON "IdentityLinkEvent"("personRef");
CREATE INDEX "IdentityLinkEvent_fromPersonRef_idx" ON "IdentityLinkEvent"("fromPersonRef");
CREATE INDEX "IdentityLinkEvent_toPersonRef_idx" ON "IdentityLinkEvent"("toPersonRef");
CREATE INDEX "IdentityMerge_survivorRef_idx" ON "IdentityMerge"("survivorRef");
CREATE INDEX "IdentityMerge_duplicateRef_idx" ON "IdentityMerge"("duplicateRef");
