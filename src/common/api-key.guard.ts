import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Compare two secrets without leaking their contents through timing.
 *
 * `a !== b` returns as soon as it finds a differing byte, so how long it takes is a
 * function of how much of the key the caller got right -- enough, over many requests, to
 * recover the key a byte at a time. Hashing first gives both sides a fixed 32-byte length
 * (timingSafeEqual throws on a length mismatch, which would itself be an oracle) and the
 * comparison is then constant-time regardless of input.
 */
function secretsEqual(presented: string, required: string): boolean {
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(required).digest();
  return timingSafeEqual(a, b);
}

/**
 * Minimal bearer/api-key guard for privileged endpoints (admin listing, audit read).
 *
 * This is the in-application half of the gateway posture. At the edge, the Ingress /
 * API gateway enforces TLS, rate limits, and coarse authn (see deploy/k8s). Here we
 * enforce a shared admin key so audit and registry data are not world-readable even
 * if the edge is bypassed. Swap this for OIDC-protected admin scopes or mTLS in a
 * hardened deployment.
 */
@Injectable()
export class AdminKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const required = process.env.ADMIN_API_KEY;
    // If no admin key is configured, refuse rather than fail open.
    if (!required) {
      throw new UnauthorizedException('Admin API key not configured on this deployment');
    }
    const req = context.switchToHttp().getRequest();
    const header: string = req.headers['authorization'] ?? req.headers['x-admin-key'] ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : header;
    if (!presented || !secretsEqual(presented, required)) {
      throw new UnauthorizedException('Invalid or missing admin API key');
    }
    return true;
  }
}
