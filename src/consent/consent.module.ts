import { Module } from '@nestjs/common';
import { ConsentController } from './consent.controller';
import { SsoModule } from '../sso/oidc.module';

// ConsentController injects OIDC_PROVIDER: revoking a consent must destroy the OIDC grant
// and its tokens, not just record the withdrawal. That token is provided (and exported)
// by SsoModule, so this module has to import it -- without this, Nest cannot resolve the
// controller and `NestFactory.create(AppModule)` throws at boot, i.e. the whole app fails
// to start. Nothing caught it because no test booted AppModule; smoke:sso-nest now does.
@Module({ imports: [SsoModule], controllers: [ConsentController] })
export class ConsentModule {}
