// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';

/**
 * The delivery-layer half of observability: the health endpoints. Logging and metrics are
 * wired in `main.ts`, before the application is created, because they have to observe the
 * application rather than be part of it. `PrismaService` comes from the global PlatformModule.
 */
@Module({ controllers: [HealthController] })
export class ObservabilityModule {}
