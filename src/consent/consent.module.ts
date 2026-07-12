import { Module } from '@nestjs/common';
import { ConsentController } from './consent.controller';

@Module({ controllers: [ConsentController] })
export class ConsentModule {}
