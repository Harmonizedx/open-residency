// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { AssuranceController, ResidentAssuranceController } from './assurance.controller';

@Module({ controllers: [AssuranceController, ResidentAssuranceController] })
export class AssuranceModule {}
