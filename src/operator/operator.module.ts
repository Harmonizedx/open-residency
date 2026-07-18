import { Module } from '@nestjs/common';
import { OperatorController } from './operator.controller';

@Module({ controllers: [OperatorController] })
export class OperatorModule {}
