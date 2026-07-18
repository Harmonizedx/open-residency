import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';
import { OperatorRole, isOperatorRole } from './operator';

/**
 * Operator SSO: validating an access token issued by the government's own identity
 * provider (Entra ID, Keycloak, Auth0, a national staff IdP).
 *
 * This is the mode a real deployment should run. It means operator accounts, password
 * policy, MFA, joiner/mover/leaver and de-provisioning all live where the ministry
 * already manages staff identity, and OpenResidency holds no staff credentials at all.
 * The local account mode exists for deployments that have no IdP yet; it is not the
 * target state.
 *
 * Verification is full JWT validation against the IdP's published JWKS -- signature,
 * issuer, audience, expiry -- with the keys fetched from the discovery document and
 * cached by `jose`. Nothing here trusts a claim without checking the signature over it.
 */

export interface FederatedOperatorConfig {
  /** The IdP's issuer URL. Must match the `iss` claim exactly. */
  issuer: string;
  /** The audience this deployment's tokens are minted for. */
  audience: string;
  /** Claim holding the operator's roles. Dot-paths allowed, e.g. `realm_access.roles`. */
  roleClaim: string;
  /** Claim holding a human-readable identifier for the audit trail. */
  nameClaim: string;
  /**
   * Map IdP group/role names onto OpenResidency roles. A ministry's directory will have
   * its own naming ("ROLE_REGISTRY_CLERK"), and renaming groups across a government
   * directory to suit one application is not a reasonable ask.
   */
  roleMap: Record<string, string>;
  /** Explicit JWKS URI. Defaults to the issuer's OIDC discovery location. */
  jwksUri?: string;
}

/** Read a dot-path out of a claim set. */
function claimAt(payload: JWTPayload, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, part) =>
        acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[part] : undefined,
      payload,
    );
}

/** Roles may arrive as an array or as a space/comma-delimited string. */
function toRoleList(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === 'string') return raw.split(/[\s,]+/).filter(Boolean);
  return [];
}

export interface FederatedClaims {
  subject: string;
  email?: string;
  displayName?: string;
  roles: OperatorRole[];
}

export class FederatedOperatorVerifier {
  private jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private cfg: FederatedOperatorConfig) {
    const uri =
      cfg.jwksUri ?? `${cfg.issuer.replace(/\/$/, '')}/.well-known/jwks.json`;
    this.jwks = createRemoteJWKSet(new URL(uri));
  }

  /**
   * Verify a bearer token and map it to operator claims.
   *
   * Returns null on any failure -- bad signature, wrong issuer or audience, expiry, or a
   * token whose roles map to nothing we recognise. A token bearing only unmapped roles is
   * an authenticated stranger, not an operator, so it is refused rather than admitted
   * with an empty role set.
   */
  async verify(token: string): Promise<FederatedClaims | null> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        issuer: this.cfg.issuer,
        audience: this.cfg.audience,
      }));
    } catch {
      return null;
    }
    if (!payload.sub) return null;

    const mapped = toRoleList(claimAt(payload, this.cfg.roleClaim))
      .map((r) => this.cfg.roleMap[r] ?? r)
      .filter(isOperatorRole);
    if (mapped.length === 0) return null;

    const email = typeof payload.email === 'string' ? payload.email : undefined;
    const nameRaw = claimAt(payload, this.cfg.nameClaim);
    return {
      subject: payload.sub,
      email,
      displayName: typeof nameRaw === 'string' ? nameRaw : email,
      roles: [...new Set(mapped)],
    };
  }
}
