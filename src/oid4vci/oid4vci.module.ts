import { Module } from '@nestjs/common';
import { Oid4vciController, Oid4vciMetadataController } from './oid4vci.controller';

@Module({ controllers: [Oid4vciController, Oid4vciMetadataController] })
export class Oid4vciModule {}
