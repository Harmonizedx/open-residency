// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { StatisticsController } from './statistics.controller';
import { ComplianceController } from './compliance.controller';

@Module({ controllers: [AdminController, StatisticsController, ComplianceController] })
export class AdminModule {}
