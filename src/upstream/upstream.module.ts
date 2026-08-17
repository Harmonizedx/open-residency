// SPDX-License-Identifier: Apache-2.0
import { Module } from '@nestjs/common';
import { UpstreamController } from './upstream.controller';

@Module({ controllers: [UpstreamController] })
export class UpstreamModule {}
