import { Module } from '@nestjs/common';
import { Oid4vpController } from './oid4vp.controller';

@Module({ controllers: [Oid4vpController] })
export class Oid4vpModule {}
