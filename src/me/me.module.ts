// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { MeController } from './me.controller';

@Module({ controllers: [MeController] })
export class MeModule {}
