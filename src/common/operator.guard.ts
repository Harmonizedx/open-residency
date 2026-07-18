import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { Operator, OperatorRole, operatorHasRole } from '../core/operator/operator';
import { PlatformService } from '../platform/platform.service';

/**
 * Authenticates and authorizes a member of staff on a privileged route.
 *
 * Replaces AdminKeyGuard, which proved only that the caller held one shared secret. This
 * resolves a specific operator and the roles they hold, attaches them to the request, and
 * lets the handler record WHO acted -- the thing the audit log could not previously say.
 *
 * Three credential forms are accepted, and which ones are live depends on
 * `operatorAuth.mode` in the country config:
 *
 *   Bearer <IdP access token>   mode: oidc    -- validated against the IdP's JWKS
 *   Bearer <session token>      mode: local   -- issued by POST /operator/login
 *   ork_... (any mode)                        -- a per-operator API key, for machine callers
 *   x-admin-key                 mode: sharedKey -- the legacy shared secret, deprecated
 *
 * Authorization is a role check declared per route with @RequireRoles. A route with no
 * declaration requires only that the caller is *some* authenticated operator.
 */

export const OPERATOR_ROLES_KEY = 'operator:roles';

/** Declare the role a route requires. `admin` always satisfies it. */
export const RequireRoles = (...roles: OperatorRole[]) => SetMetadata(OPERATOR_ROLES_KEY, roles);

/** The authenticated operator, for handlers that need to name the actor. */
export interface RequestWithOperator extends Request {
  operator?: Operator;
}

export function requireOperator(req: RequestWithOperator): Operator {
  if (!req.operator) {
    // Unreachable through the guard; a defensive check so a handler can never silently
    // attribute an action to nobody if it is ever mounted without one.
    throw new UnauthorizedException('No authenticated operator on this request');
  }
  return req.operator;
}

@Injectable()
export class OperatorGuard implements CanActivate {
  private readonly log = new Logger('OperatorGuard');

  constructor(
    private platform: PlatformService,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithOperator>();
    const operator = await this.authenticate(req);
    if (!operator) throw new UnauthorizedException('Operator authentication required');

    const required =
      this.reflector.getAllAndOverride<OperatorRole[] | undefined>(OPERATOR_ROLES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    // Any ONE of the declared roles is enough: a route is usually reachable by more than
    // one job function (a registrar and an admin both enrol).
    if (required.length > 0 && !required.some((r) => operatorHasRole(operator, r))) {
      // Logged with the operator's name because a denied privileged action is exactly the
      // kind of event an investigation needs, and it is not sensitive.
      this.log.warn(
        `Operator ${operator.displayName} lacks ${required.join('/')} for ${req.method} ${req.path}`,
      );
      throw new ForbiddenException(
        `This action requires the ${required.join(' or ')} role`,
      );
    }

    req.operator = operator;
    return true;
  }

  private bearer(req: Request): string | undefined {
    const header = String(req.headers['authorization'] ?? '');
    return header.startsWith('Bearer ') ? header.slice(7).trim() : undefined;
  }

  private async authenticate(req: Request): Promise<Operator | null> {
    const auth = this.platform.getOperatorAuth();
    const token = this.bearer(req);

    // Per-operator API keys work in every mode: they are how kiosks and batch jobs
    // authenticate, and they carry an identity and an expiry unlike the shared key.
    const presentedKey =
      (token?.startsWith('ork_') ? token : undefined) ??
      (String(req.headers['x-operator-key'] ?? '') || undefined);
    if (presentedKey) {
      return auth.operators.authenticateKey(presentedKey);
    }

    if (auth.mode === 'oidc' && token) {
      if (!auth.federated) return null;
      const claims = await auth.federated.verify(token);
      if (!claims) return null;
      return auth.operators.resolveFederated(claims);
    }

    if (auth.mode === 'local' && token) {
      if (!auth.sessions) return null;
      const session = await auth.sessions.verify(token);
      if (!session) return null;
      return auth.operators.resolveSession(session.operatorId);
    }

    if (auth.mode === 'sharedKey') {
      const required = process.env.ADMIN_API_KEY;
      if (!required) return null;
      const header = String(req.headers['x-admin-key'] ?? '') || token || '';
      if (!header || !auth.sharedKeyMatches(header)) return null;
      // The legacy path. It cannot name a person, so it is attributed to the key itself --
      // which is at least truthful, unlike the previous 'admin'.
      return {
        id: 'shared-admin-key',
        displayName: 'shared-admin-key',
        roles: ['admin'],
        via: 'sharedKey',
      };
    }

    return null;
  }
}
