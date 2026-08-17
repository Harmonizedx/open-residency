-- Pending authorizations at an external OpenID Provider.
--
-- Additive, per ORRA §15: a new table only, nothing existing is altered, so a deployment
-- that never configures `upstreamOidc` is unaffected by it.
--
-- The two halves of an OIDC redirect are separate HTTP requests that will not land on the
-- same replica, which is why this is a table and not in-process state. `state` is the
-- primary key so a replayed callback consuming an already-deleted row finds nothing.
CREATE TABLE "UpstreamAuthRequest" (
    "state" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "codeVerifier" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UpstreamAuthRequest_pkey" PRIMARY KEY ("state")
);

CREATE INDEX "UpstreamAuthRequest_createdAt_idx" ON "UpstreamAuthRequest"("createdAt");
