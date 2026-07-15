import { Module } from '@nestjs/common';
import { VcApiController } from './vcapi.controller';

@Module({ controllers: [VcApiController] })
export class VcApiModule {}
