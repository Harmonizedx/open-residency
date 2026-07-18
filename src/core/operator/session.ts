import { SignJWT, jwtVerify, type KeyLike } from 'jose';
import { Operator, OperatorRole, isOperatorRole } from './operator';

/**
 * Short-lived session tokens for operators who signed in with a local account.
 *
 * Signed with the deployment's own issuer key, so there is no additional secret to
 * manage, and short-lived by design: a console session is not a long-lived credential.
 * Machine callers use API keys (which rotate) instead of these.
 *
 * The token carries roles, but the guard re-reads the operator record on every request
 * anyway -- so disabling an account takes effect immediately rather than at the end of
 * the token's lifetime. The claims here are a hint, not the authority.
 */

const AUDIENCE = 'openresidency-operator';

export class OperatorSessions {
  constructor(
    private privateKey: KeyLike,
    private publicKey: KeyLike,
    private issuer: string,
    private ttlSeconds = 8 * 3600,
  ) {}

  async issue(operator: Operator): Promise<{ token: string; expiresIn: number }> {
    const token = await new SignJWT({
      roles: operator.roles,
      name: operator.displayName,
    })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setSubject(operator.id)
      .setIssuer(this.issuer)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSeconds}s`)
      .sign(this.privateKey);
    return { token, expiresIn: this.ttlSeconds };
  }

  /** Verify a session token. Returns the operator id and claimed roles, or null. */
  async verify(token: string): Promise<{ operatorId: string; roles: OperatorRole[] } | null> {
    try {
      const { payload } = await jwtVerify(token, this.publicKey, {
        issuer: this.issuer,
        audience: AUDIENCE,
      });
      if (!payload.sub) return null;
      const roles = Array.isArray(payload.roles)
        ? payload.roles.map(String).filter(isOperatorRole)
        : [];
      return { operatorId: payload.sub, roles };
    } catch {
      return null;
    }
  }
}
