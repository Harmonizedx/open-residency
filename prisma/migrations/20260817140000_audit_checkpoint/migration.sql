-- Signed anchors for the audit chain (issue #26).
--
-- Additive, per ORRA §15: a new table only. A deployment that never checkpoints is exactly
-- as it was, and verifyChain reports `anchored: false` rather than silently passing.
--
-- `seq` is the primary key: one checkpoint per head position, so re-checkpointing an
-- unchanged log cannot accumulate duplicate rows.
CREATE TABLE "AuditCheckpoint" (
    "seq" INTEGER NOT NULL,
    "hash" TEXT NOT NULL,
    "count" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signature" TEXT NOT NULL,
    "kid" TEXT NOT NULL,

    CONSTRAINT "AuditCheckpoint_pkey" PRIMARY KEY ("seq")
);

CREATE INDEX "AuditCheckpoint_createdAt_idx" ON "AuditCheckpoint"("createdAt");
