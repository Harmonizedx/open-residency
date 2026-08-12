// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { ResidencyController } from './residency.controller';

@Module({ controllers: [ResidencyController] })
export class ResidencyModule {}
