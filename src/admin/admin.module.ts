import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { StatisticsController } from './statistics.controller';

@Module({ controllers: [AdminController, StatisticsController] })
export class AdminModule {}
