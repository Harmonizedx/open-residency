// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { AuditController } from './audit.controller';

@Module({ controllers: [AuditController] })
export class AuditModule {}
