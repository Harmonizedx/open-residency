// SPDX-License-Identifier: Apache-2.0
import { Injectable, Logger } from '@nestjs/common';
import { secretsEqual } from '../core/kernel/secrets';
import { CountryConfig } from '../core/config/country-config';
import { IssuerKey } from '../core/credentials/keystore';
import { OperatorService } from '../core/operator/operator';
import { FederatedOperatorVerifier } from '../core/operator/federated';
import { OperatorSessions } from '../core/operator/session';
import { PrismaOperatorStore } from '../prisma/prisma.service';

/**
 * Everything the OperatorGuard needs to authenticate a member of staff, assembled once at
 * boot from `operatorAuth` in the default country config.
 */
export interface OperatorAuthContext {
  mode: 'oidc' | 'local' | 'sharedKey';
  operators: OperatorService;
  federated?: FederatedOperatorVerifier;
  sessions?: OperatorSessions;
  sharedKeyMatches(presented: string): boolean;
}

export interface OperatorIdentityDeps {
  issuerKey: IssuerKey;
  publicBaseUrl: () => string;
}

/**
 * How a member of staff proves who they are, and how the first one comes to exist.
 *
 * Its own concern because it answers a question nothing else in the platform asks: not
 * "what can this deployment do" but "who is asking". The three modes are genuinely
 * different trust arrangements -- an external IdP holding staff identity, local accounts
 * with TOTP, or a single shared key that can name nobody -- and the choice between them
 * belongs with the code that implements them rather than beside the wiring of residency.
 *
 * Bootstrap lives here for the same reason. A register with privileged endpoints and no
 * operator is unusable, and one that quietly creates an admin without telling anyone is
 * worse; both are properties of operator identity, not of platform composition.
 */
@Injectable()
export class OperatorIdentity {
  private readonly log = new Logger('OperatorIdentity');
  private context!: OperatorAuthContext;
  private deps!: OperatorIdentityDeps;

  constructor(private store: PrismaOperatorStore) {}

  /** Assemble the auth context and ensure an operator exists to use it. */
  async init(cfg: CountryConfig | undefined, deps: OperatorIdentityDeps): Promise<void> {
    this.deps = deps;
    this.context = this.build(cfg);
    await this.bootstrap();
  }

  private build(cfg?: CountryConfig): OperatorAuthContext {
    const conf = cfg?.operatorAuth ?? {
      mode: 'sharedKey' as const,
      issuerName: 'OpenResidency',
      local: { requireMfa: true, sessionTtlSeconds: 8 * 3600 },
    };
    const operators = new OperatorService(this.store, {
      requireMfa: conf.local.requireMfa,
      issuerName: conf.issuerName,
    });

    const ctx: OperatorAuthContext = {
      mode: conf.mode,
      operators,
      sharedKeyMatches: (presented: string) => {
        const required = process.env.ADMIN_API_KEY;
        if (!required) return false;
        return secretsEqual(presented, required);
      },
    };

    if (conf.mode === 'oidc') {
      ctx.federated = new FederatedOperatorVerifier({
        issuer: conf.oidc!.issuer,
        audience: conf.oidc!.audience,
        roleClaim: conf.oidc!.roleClaim,
        nameClaim: conf.oidc!.nameClaim,
        roleMap: conf.oidc!.roleMap,
        jwksUri: conf.oidc!.jwksUri,
      });
      this.log.log(`Operator auth: OIDC (issuer ${conf.oidc!.issuer})`);
    } else if (conf.mode === 'local') {
      ctx.sessions = new OperatorSessions(
        this.deps.issuerKey.signer,
        this.deps.issuerKey.publicKey,
        this.deps.publicBaseUrl(),
        conf.local.sessionTtlSeconds,
      );
      this.log.log(
        `Operator auth: local accounts (MFA ${conf.local.requireMfa ? 'required' : 'optional'})`,
      );
    } else {
      this.log.warn(
        'Operator auth: shared ADMIN_API_KEY. This carries no operator identity, so every ' +
          'privileged action audits to the same actor, there are no roles, and rotation ' +
          'requires a restart. Set operatorAuth.mode to `oidc` before government staff use ' +
          'this deployment.',
      );
    }
    return ctx;
  }

  /**
   * Create the first admin from the environment, once, if no operators exist.
   *
   * Without this there is no way into a `local` deployment: every operator-management
   * route requires an operator. The TOTP secret is logged exactly once, on the boot that
   * creates the account, because there is nowhere else for it to go -- and the account is
   * useless without it.
   */
  private async bootstrap(): Promise<void> {
    const email = process.env.OPERATOR_BOOTSTRAP_EMAIL;
    const password = process.env.OPERATOR_BOOTSTRAP_PASSWORD;
    if (!email || !password) return;
    if ((await this.context.operators.count()) > 0) return;
    const { totpSecret, totpUri } = await this.context.operators.createOperator({
      email,
      displayName: email,
      roles: ['admin'],
      password,
    });
    this.log.warn(
      `Bootstrapped the first operator account ${email} with the admin role. ` +
        `Enrol this TOTP secret in an authenticator app now -- it is not shown again: ${totpSecret}`,
    );
    this.log.warn(`Enrolment URI: ${totpUri}`);
  }

  getContext(): OperatorAuthContext {
    return this.context;
  }
}
