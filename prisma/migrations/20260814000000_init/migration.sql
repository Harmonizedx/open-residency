-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "Resident" (
    "id" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "subjectRef" TEXT NOT NULL,
    "countryCode" TEXT NOT NULL,
    "subnationalUnit" TEXT NOT NULL,
    "providerCode" TEXT NOT NULL,
    "assuranceLevel" TEXT NOT NULL,
    "bindingMethod" TEXT NOT NULL DEFAULT 'none',
    "bindingRef" TEXT,
    "bindingAt" TIMESTAMP(3),
    "bindingScore" DOUBLE PRECISION,
    "residenceAssurance" TEXT NOT NULL DEFAULT 'RAL0',
    "residenceMethod" TEXT NOT NULL DEFAULT 'self_declared',
    "residenceUnit" TEXT,
    "residenceAsOf" TIMESTAMP(3),
    "provisional" BOOLEAN NOT NULL DEFAULT false,
    "credentialId" TEXT,
    "statusListIndex" INTEGER NOT NULL,
    "fullName" TEXT,
    "givenName" TEXT,
    "familyName" TEXT,
    "dateOfBirth" TEXT,
    "gender" TEXT,
    "phoneHash" TEXT,
    "phoneEnc" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "erasedAt" TIMESTAMP(3),

    CONSTRAINT "Resident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StatusListState" (
    "countryCode" TEXT NOT NULL,
    "encodedList" TEXT NOT NULL,
    "nextIndex" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "StatusListState_pkey" PRIMARY KEY ("countryCode")
);

-- CreateTable
CREATE TABLE "CredentialOffer" (
    "id" TEXT NOT NULL,
    "preAuthorizedCodeHash" TEXT NOT NULL,
    "txCodeHash" TEXT,
    "residentId" TEXT NOT NULL,
    "countryCode" TEXT NOT NULL,
    "configurationIds" TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "redeemedAt" TIMESTAMP(3),
    "failedAttempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CredentialOffer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Oid4vciNonce" (
    "nonceHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Oid4vciNonce_pkey" PRIMARY KEY ("nonceHash")
);

-- CreateTable
CREATE TABLE "PresentationRequest" (
    "id" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "reference" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "outcome" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PresentationRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OtpChallenge" (
    "id" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumed" BOOLEAN NOT NULL DEFAULT false,
    "failedAttempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OtpChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "seq" INTEGER NOT NULL,
    "eventId" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "action" TEXT NOT NULL,
    "actor" TEXT NOT NULL,
    "target" TEXT,
    "countryCode" TEXT,
    "outcome" TEXT NOT NULL,
    "metadata" JSONB,
    "prevHash" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "redactedAt" TIMESTAMP(3),

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("seq")
);

-- CreateTable
CREATE TABLE "Operator" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "roles" TEXT[],
    "passwordHash" TEXT,
    "totpSecret" TEXT,
    "totpConfirmedAt" TIMESTAMP(3),
    "failedLogins" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "disabledAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Operator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OperatorKey" (
    "id" TEXT NOT NULL,
    "operatorId" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "rotatedFrom" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OperatorKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConsentRecord" (
    "id" TEXT NOT NULL,
    "subjectRef" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "relyingParty" TEXT NOT NULL,
    "relyingPartyName" TEXT,
    "purpose" TEXT NOT NULL,
    "scopes" TEXT[],
    "status" TEXT NOT NULL DEFAULT 'active',
    "grantedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "receiptId" TEXT NOT NULL,
    "grantId" TEXT,

    CONSTRAINT "ConsentRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebAuthnCredential" (
    "id" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "publicJwk" JSONB NOT NULL,
    "alg" TEXT NOT NULL,
    "signCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "WebAuthnCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebAuthnChallenge" (
    "id" TEXT NOT NULL,
    "residentId" TEXT NOT NULL,
    "challenge" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumed" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebAuthnChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OidcStoredItem" (
    "name" TEXT NOT NULL,
    "id" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "grantId" TEXT,
    "uid" TEXT,
    "userCode" TEXT,
    "expiresAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OidcStoredItem_pkey" PRIMARY KEY ("name","id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Resident_residentId_key" ON "Resident"("residentId");

-- CreateIndex
CREATE UNIQUE INDEX "Resident_subjectRef_key" ON "Resident"("subjectRef");

-- CreateIndex
CREATE INDEX "Resident_countryCode_subnationalUnit_idx" ON "Resident"("countryCode", "subnationalUnit");

-- CreateIndex
CREATE UNIQUE INDEX "CredentialOffer_preAuthorizedCodeHash_key" ON "CredentialOffer"("preAuthorizedCodeHash");

-- CreateIndex
CREATE INDEX "CredentialOffer_residentId_idx" ON "CredentialOffer"("residentId");

-- CreateIndex
CREATE INDEX "CredentialOffer_expiresAt_idx" ON "CredentialOffer"("expiresAt");

-- CreateIndex
CREATE INDEX "Oid4vciNonce_expiresAt_idx" ON "Oid4vciNonce"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "PresentationRequest_nonce_key" ON "PresentationRequest"("nonce");

-- CreateIndex
CREATE INDEX "PresentationRequest_expiresAt_idx" ON "PresentationRequest"("expiresAt");

-- CreateIndex
CREATE INDEX "OtpChallenge_residentId_createdAt_idx" ON "OtpChallenge"("residentId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuditEvent_eventId_key" ON "AuditEvent"("eventId");

-- CreateIndex
CREATE INDEX "AuditEvent_target_idx" ON "AuditEvent"("target");

-- CreateIndex
CREATE INDEX "AuditEvent_action_idx" ON "AuditEvent"("action");

-- CreateIndex
CREATE UNIQUE INDEX "Operator_email_key" ON "Operator"("email");

-- CreateIndex
CREATE UNIQUE INDEX "OperatorKey_keyHash_key" ON "OperatorKey"("keyHash");

-- CreateIndex
CREATE INDEX "OperatorKey_operatorId_idx" ON "OperatorKey"("operatorId");

-- CreateIndex
CREATE INDEX "ConsentRecord_residentId_idx" ON "ConsentRecord"("residentId");

-- CreateIndex
CREATE INDEX "ConsentRecord_relyingParty_idx" ON "ConsentRecord"("relyingParty");

-- CreateIndex
CREATE UNIQUE INDEX "WebAuthnCredential_credentialId_key" ON "WebAuthnCredential"("credentialId");

-- CreateIndex
CREATE INDEX "WebAuthnCredential_residentId_idx" ON "WebAuthnCredential"("residentId");

-- CreateIndex
CREATE INDEX "WebAuthnChallenge_residentId_idx" ON "WebAuthnChallenge"("residentId");

-- CreateIndex
CREATE INDEX "OidcStoredItem_name_grantId_idx" ON "OidcStoredItem"("name", "grantId");

-- CreateIndex
CREATE INDEX "OidcStoredItem_name_uid_idx" ON "OidcStoredItem"("name", "uid");

-- CreateIndex
CREATE INDEX "OidcStoredItem_name_userCode_idx" ON "OidcStoredItem"("name", "userCode");

-- CreateIndex
CREATE INDEX "OidcStoredItem_expiresAt_idx" ON "OidcStoredItem"("expiresAt");

-- AddForeignKey
ALTER TABLE "OperatorKey" ADD CONSTRAINT "OperatorKey_operatorId_fkey" FOREIGN KEY ("operatorId") REFERENCES "Operator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

