// SPDX-License-Identifier: Apache-2.0
import { Logger } from '@nestjs/common';
import { AuditLog } from '../core/audit/audit-log';
import { PrismaOidcStore } from '../prisma/prisma.service';

/**
 * What this deployment does on a timer, and when it stops.
 *
 * Three jobs that share nothing except the shape of the problem: each protects a guarantee
 * that decays if nobody re-establishes it. The audit head goes unanchored, a peer's
 * revocations go unnoticed, expired OIDC state accumulates. None of them is part of serving
 * a request, which is why they do not belong in the class that wires up request serving.
 *
 * Collected here mainly so that shutdown is one thing rather than three: every timer is
 * unref'd so it cannot hold the process open, and `stop()` clears all of them. A background
 * job whose only stop path is a scattered clearInterval in a destructor is how a test suite
 * ends up hanging for reasons nobody can find.
 */
export interface BackgroundJobDeps {
  audit: AuditLog;
  oidcStore: PrismaOidcStore;
  /** Peers are resolved lazily: federation is configured after this is constructed. */
  federatedPeers: () => unknown[];
  syncFederatedStatusLists: () => Promise<unknown>;
}

export class BackgroundJobs {
  private readonly log = new Logger('BackgroundJobs');
  private federationTimer?: NodeJS.Timeout;
  private oidcPurgeTimer?: NodeJS.Timeout;
  private auditCheckpointTimer?: NodeJS.Timeout;

  constructor(private deps: BackgroundJobDeps) {}

  /** Start every job. Each decides for itself whether it is enabled. */
  start(): void {
    this.startAuditCheckpoints();
    this.startFederationRefresh();
    this.startOidcPurge();
  }

  /** Stop every job. Safe to call when none were started. */
  stop(): void {
    for (const t of [this.federationTimer, this.oidcPurgeTimer, this.auditCheckpointTimer]) {
      if (t) clearInterval(t);
    }
  }


  /**
   * Commit to the audit head on an interval, and sign it.
   *
   * The interval IS the exposure: events appended since the last checkpoint are the ones a
   * tail truncation could still take undetected, so a deployment answerable for its log
   * should shorten it rather than accept the default. `AUDIT_CHECKPOINT_SECONDS=0` disables
   * it for deployments that anchor externally on their own schedule.
   *
   * One is written at startup too. A process that ran, recorded events, and was restarted
   * before its first interval elapsed would otherwise leave that whole window unanchored.
   */
  private startAuditCheckpoints(): void {
    const seconds = Number(process.env.AUDIT_CHECKPOINT_SECONDS ?? 300);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      this.log.warn(
        'Audit checkpoints are disabled: the chain can detect edits and reordering, but not ' +
          'having its tail cut. Anchor it externally, or set AUDIT_CHECKPOINT_SECONDS.',
      );
      return;
    }
    const write = () =>
      void this.deps.audit
        .checkpoint()
        .catch((e) => this.log.warn(`Audit checkpoint failed: ${(e as Error).message}`));
    write();
    this.auditCheckpointTimer = setInterval(write, seconds * 1000);
    this.auditCheckpointTimer.unref?.();
  }

  /**
   * Re-sync peer status lists on an interval, because a revocation published by a peer is
   * only as timely as our last pull. `FEDERATION_STATUS_REFRESH_SECONDS=0` disables it for
   * deployments that drive the sync themselves.
   */
  private startFederationRefresh(): void {
    if (!this.deps.federatedPeers().length) return;
    const seconds = Number(process.env.FEDERATION_STATUS_REFRESH_SECONDS ?? 900);
    if (!Number.isFinite(seconds) || seconds <= 0) return;
    this.federationTimer = setInterval(() => {
      void this.deps.syncFederatedStatusLists().catch((e) =>
        this.log.warn(`Federation: status refresh failed: ${(e as Error).message}`),
      );
    }, seconds * 1000);
    // Do not hold the process open for a cache refresh.
    this.federationTimer.unref?.();
  }

  /**
   * Delete OIDC provider state that has already expired.
   *
   * Nothing reads an expired row -- `PrismaOidcStore` filters on every lookup -- but
   * without a sweep they accumulate for the life of the deployment. This is the busiest
   * table in the system: a row per authorization code, access token, refresh token and
   * session, for every sign-in to every sector service. Left alone it becomes the largest
   * thing in the database and the reason its backups stop fitting.
   *
   * Every replica runs this, which is harmless: the delete is idempotent and the losers of
   * a race simply remove nothing. `OIDC_PURGE_INTERVAL_SECONDS=0` disables it for
   * deployments that would rather sweep from cron.
   */
  private startOidcPurge(): void {
    const seconds = Number(process.env.OIDC_PURGE_INTERVAL_SECONDS ?? 3600);
    if (!Number.isFinite(seconds) || seconds <= 0) return;
    this.oidcPurgeTimer = setInterval(() => {
      void this.deps.oidcStore
        .purgeExpired(new Date())
        .then((n) => {
          if (n > 0) this.log.log(`OIDC: swept ${n} expired provider record(s)`);
        })
        .catch((e) => this.log.warn(`OIDC: expiry sweep failed: ${(e as Error).message}`));
    }, seconds * 1000);
    // A housekeeping sweep must not keep the process alive.
    this.oidcPurgeTimer.unref?.();
  }
}
