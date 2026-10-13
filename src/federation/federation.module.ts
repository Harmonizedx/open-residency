// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { FederationController } from './federation.controller';

@Module({ controllers: [FederationController] })
export class FederationModule {}
