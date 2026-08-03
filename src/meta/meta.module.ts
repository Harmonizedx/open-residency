// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { MetaController } from './meta.controller';

@Module({ controllers: [MetaController] })
export class MetaModule {}
