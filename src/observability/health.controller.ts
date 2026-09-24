// SPDX-License-Identifier: Apache-2.0
import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Liveness and readiness, for the orchestrator.
 *
 * The probes used to hit `GET /residency/countries`, which lists configs held in memory: a
 * pod whose database had gone answered it 200 and kept receiving traffic, every request of
 * which then failed. Readiness has to ask the dependency the requests need.
 *
 * Both are unauthenticated and exempt from the rate limiter -- a kubelet holds no operator
 * key, and a probe that is answered 429 under load is a pod that is killed under load. Neither
 * says anything about the deployment beyond "up" and "can reach its database", and a failure
 * names the check that failed, never the error: a connection string inside an exception
 * message is not something to hand to whoever can reach this port.
 */
const READY_TIMEOUT_MS = 2000;

@Controller('health')
@SkipThrottle()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  /** The process is up and answering HTTP. Nothing else is asserted. */
  @Get('live')
  live() {
    return { status: 'ok' };
  }

  /** The process can serve requests: the database answers within the timeout. */
  @Get('ready')
  async ready() {
    const database = await this.databaseAnswers();
    if (!database) {
      throw new ServiceUnavailableException({
        status: 'unavailable',
        checks: { database: 'failed' },
      });
    }
    return { status: 'ok', checks: { database: 'ok' } };
  }

  private async databaseAnswers(): Promise<boolean> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), READY_TIMEOUT_MS);
    });
    try {
      return await Promise.race([
        this.prisma.$queryRaw`SELECT 1`.then(
          () => true,
          () => false,
        ),
        timeout,
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
