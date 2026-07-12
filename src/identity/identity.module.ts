import { Module } from '@nestjs/common';
import { IdentityController } from './identity.controller';

@Module({ controllers: [IdentityController] })
export class IdentityModule {}
