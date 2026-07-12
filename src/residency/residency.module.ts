import { Module } from '@nestjs/common';
import { ResidencyController } from './residency.controller';

@Module({ controllers: [ResidencyController] })
export class ResidencyModule {}
