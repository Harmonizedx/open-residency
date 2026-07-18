import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { OperatorGuard, RequireRoles, RequestWithOperator, requireOperator } from '../common/operator.guard';
import { OPERATOR_ROLES, OperatorRole, isOperatorRole, operatorActor } from '../core/operator/operator';
import { PlatformService } from '../platform/platform.service';

/**
 * Operator account and credential management.
 *
 * Under `operatorAuth.mode: oidc` most of this is inert -- the ministry's directory owns
 * accounts, passwords and MFA, and the only useful routes here are the API-key ones for
 * machine callers and the local disable switch. Under `local` this is the whole staff
 * identity surface.
 *
 * Every route that changes anything is audited with the acting operator's name, which is
 * the point of the whole module: privileged actions become attributable.
 */
@Controller('operator')
export class OperatorController {
  constructor(private platform: PlatformService) {}

  /**
   * Local sign-in: password plus TOTP, in exchange for a short-lived session token.
   *
   * Deliberately vague on failure. Distinguishing "no such account" from "wrong password"
   * turns this into a directory of who works here, and distinguishing "wrong TOTP" from
   * "wrong password" tells an attacker which half they have already got right.
   */
  @Post('login')
  async login(@Body() body: { email?: string; password?: string; totp?: string }) {
    const auth = this.platform.getOperatorAuth();
    if (auth.mode !== 'local' || !auth.sessions) {
      throw new BadRequestException(
        'This deployment does not use local operator accounts. Sign in through the configured identity provider.',
      );
    }
    if (!body?.email || !body?.password) {
      throw new BadRequestException('email and password are required');
    }

    const result = await auth.operators.login(body.email, body.password, body.totp);
    if (!result.ok) {
      await this.platform.getAudit().record({
        action: 'operator.login',
        actor: `operator:${body.email}`,
        outcome: 'failure',
        metadata: { reason: result.reason },
      });
      // MFA_REQUIRED is the one reason worth telling the caller precisely: the console has
      // to know to prompt for a code, and it only leaks that a correct password was
      // supplied to someone who already supplied it.
      if (result.reason === 'MFA_REQUIRED') {
        return { mfaRequired: true };
      }
      throw new UnauthorizedException('Sign-in failed');
    }

    const { token, expiresIn } = await auth.sessions.issue(result.operator);
    await this.platform.getAudit().record({
      action: 'operator.login',
      actor: operatorActor(result.operator),
      outcome: 'success',
      metadata: { roles: result.operator.roles },
    });
    return {
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn,
      operator: {
        id: result.operator.id,
        displayName: result.operator.displayName,
        roles: result.operator.roles,
      },
    };
  }

  /** Who the caller is, as this deployment sees them. Useful for a console to render itself. */
  @UseGuards(OperatorGuard)
  @Get('me')
  me(@Req() req: RequestWithOperator) {
    const op = requireOperator(req);
    return { id: op.id, displayName: op.displayName, roles: op.roles, via: op.via };
  }

  @UseGuards(OperatorGuard)
  @RequireRoles('admin')
  @Get('operators')
  async list() {
    const operators = await this.platform.getOperatorAuth().operators.listOperators();
    // Never return the TOTP secret or the password hash, even to an admin: an admin is
    // authorized to manage accounts, not to impersonate their holders.
    return {
      operators: operators.map((o) => ({
        id: o.id,
        email: o.email,
        displayName: o.displayName,
        roles: o.roles,
        mfaEnrolled: !!o.totpConfirmedAt,
        disabled: !!o.disabledAt,
        createdAt: o.createdAt,
      })),
    };
  }

  /**
   * Create an operator. The TOTP secret is returned exactly once, here: it has to reach
   * an authenticator app somehow, and it is never recoverable afterwards.
   */
  @UseGuards(OperatorGuard)
  @RequireRoles('admin')
  @Post('operators')
  async create(
    @Req() req: RequestWithOperator,
    @Body() body: { email?: string; displayName?: string; roles?: string[]; password?: string },
  ) {
    const actor = requireOperator(req);
    if (!body?.email) throw new BadRequestException('email is required');
    const roles = (body.roles ?? []).filter(isOperatorRole) as OperatorRole[];
    if (roles.length === 0) {
      throw new BadRequestException(`roles must include at least one of: ${OPERATOR_ROLES.join(', ')}`);
    }

    let created;
    try {
      created = await this.platform.getOperatorAuth().operators.createOperator({
        email: body.email,
        displayName: body.displayName,
        roles,
        password: body.password,
      });
    } catch (e) {
      throw new BadRequestException((e as Error).message);
    }

    await this.platform.getAudit().record({
      action: 'operator.create',
      actor: operatorActor(actor),
      target: body.email,
      outcome: 'success',
      metadata: { roles },
    });
    return {
      id: created.record.id,
      email: created.record.email,
      roles: created.record.roles,
      totpSecret: created.totpSecret,
      totpUri: created.totpUri,
    };
  }

  @UseGuards(OperatorGuard)
  @RequireRoles('admin')
  @Post('operators/:id/disable')
  async disable(@Req() req: RequestWithOperator, @Body() body: { operatorId?: string; disabled?: boolean }) {
    const actor = requireOperator(req);
    if (!body?.operatorId) throw new BadRequestException('operatorId is required');
    const disabled = body.disabled !== false;
    const ok = await this.platform.getOperatorAuth().operators.setDisabled(body.operatorId, disabled);
    await this.platform.getAudit().record({
      action: disabled ? 'operator.disable' : 'operator.enable',
      actor: operatorActor(actor),
      target: body.operatorId,
      outcome: ok ? 'success' : 'failure',
    });
    return { ok };
  }

  // ---- API keys -----------------------------------------------------------

  @UseGuards(OperatorGuard)
  @Get('keys')
  async keys(@Req() req: RequestWithOperator) {
    const op = requireOperator(req);
    const keys = await this.platform.getOperatorAuth().operators.listKeys(op.id);
    return {
      keys: keys.map((k) => ({
        id: k.id,
        label: k.label,
        expiresAt: k.expiresAt,
        lastUsedAt: k.lastUsedAt,
        revokedAt: k.revokedAt,
        rotatedFrom: k.rotatedFrom,
        createdAt: k.createdAt,
      })),
    };
  }

  /** Mint an API key for the calling operator. The plaintext is shown once. */
  @UseGuards(OperatorGuard)
  @Post('keys')
  async createKey(
    @Req() req: RequestWithOperator,
    @Body() body: { label?: string; expiresInDays?: number },
  ) {
    const op = requireOperator(req);
    if (op.via === 'sharedKey') {
      throw new BadRequestException(
        'The shared admin key has no operator identity to attach a key to. Configure operatorAuth.mode oidc or local first.',
      );
    }
    const issued = await this.platform.getOperatorAuth().operators.issueKey({
      operatorId: op.id,
      label: body?.label ?? 'unnamed',
      // Default to a bounded life. A credential with no expiry is one nobody ever gets
      // round to retiring, which is how the shared static key survived as long as it did.
      expiresInDays: body?.expiresInDays ?? 90,
    });
    if (!issued) throw new BadRequestException('Could not issue a key for this operator');
    await this.platform.getAudit().record({
      action: 'operator.key.create',
      actor: operatorActor(op),
      target: issued.record.id,
      outcome: 'success',
      metadata: { label: issued.record.label, expiresAt: issued.record.expiresAt },
    });
    return { id: issued.record.id, key: issued.key, expiresAt: issued.record.expiresAt };
  }

  /**
   * Rotate a key: issue a replacement and put the old one on a short expiry, so callers
   * cut over one at a time instead of all at once.
   */
  @UseGuards(OperatorGuard)
  @Post('keys/rotate')
  async rotateKey(
    @Req() req: RequestWithOperator,
    @Body() body: { keyId?: string; overlapHours?: number },
  ) {
    const op = requireOperator(req);
    if (!body?.keyId) throw new BadRequestException('keyId is required');
    const own = await this.platform.getOperatorAuth().operators.listKeys(op.id);
    // An operator rotates their own keys; an admin may rotate anyone's.
    if (!own.some((k) => k.id === body.keyId) && !op.roles.includes('admin')) {
      throw new UnauthorizedException('That key belongs to another operator');
    }
    const rotated = await this.platform
      .getOperatorAuth()
      .operators.rotateKey(body.keyId, body.overlapHours ?? 24);
    if (!rotated) throw new BadRequestException('Unknown or already revoked key');
    await this.platform.getAudit().record({
      action: 'operator.key.rotate',
      actor: operatorActor(op),
      target: body.keyId,
      outcome: 'success',
      metadata: { replacementId: rotated.record.id, oldKeyRetiresAt: rotated.retiresAt },
    });
    return { id: rotated.record.id, key: rotated.key, oldKeyRetiresAt: rotated.retiresAt };
  }

  @UseGuards(OperatorGuard)
  @Post('keys/revoke')
  async revokeKey(@Req() req: RequestWithOperator, @Body() body: { keyId?: string }) {
    const op = requireOperator(req);
    if (!body?.keyId) throw new BadRequestException('keyId is required');
    const own = await this.platform.getOperatorAuth().operators.listKeys(op.id);
    if (!own.some((k) => k.id === body.keyId) && !op.roles.includes('admin')) {
      throw new UnauthorizedException('That key belongs to another operator');
    }
    const ok = await this.platform.getOperatorAuth().operators.revokeKey(body.keyId);
    await this.platform.getAudit().record({
      action: 'operator.key.revoke',
      actor: operatorActor(op),
      target: body.keyId,
      outcome: ok ? 'success' : 'failure',
    });
    return { revoked: ok };
  }
}
