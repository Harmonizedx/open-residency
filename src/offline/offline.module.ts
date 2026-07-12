import { Module } from '@nestjs/common';
import { OfflineController } from './offline.controller';
import { WellKnownController } from '../credentials/well-known.controller';

@Module({ controllers: [OfflineController, WellKnownController] })
export class OfflineModule {}
