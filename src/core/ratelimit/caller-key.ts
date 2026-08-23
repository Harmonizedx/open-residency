// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';

/**
 * Who a rate limit counts against (ADR-0013).
 *
 * Framework-free and pure: the delivery layer reads the headers, this decides. That keeps the
 * decision testable without booting an application, which matters because the defect this
 * replaces was invisible precisely because nothing exercised it.
 */
export interface CallerKeyInput {
  /**
   * The credential the caller presented, verbatim -- an `ork_...` operator key or a bearer
   * token. NOT the resolved operator: resolving one costs a database round trip, and a rate
   * limiter runs before and on every request. The credential identifies the caller well
   * enough to budget them, and cannot be forged for someone else.
   */
  credential?: string;
  /** The `X-Forwarded-For` header, verbatim, if present. */
  forwardedFor?: string;
  /** The socket address the request arrived from. */
  remoteAddress?: string;
  /** How many proxies the deployment declares sit in front. 0 means direct exposure. */
  trustedHops: number;
}

export interface CallerKey {
  /** The bucket this request counts against. */
  key: string;
  /** What identified the caller, for logging and for tests to assert on. */
  source: 'operator' | 'address' | 'unattributable';
  /**
   * The request carries a forwarding header while the deployment declares no proxy, so the
   * address being counted is a proxy's rather than a caller's. The limit is not doing what it
   * appears to do, and the caller of this function is expected to say so out loud.
   */
  proxyMismatch: boolean;
}

/** Not the credential itself: a rate-limit key ends up in memory, logs and metrics. */
function fingerprint(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 32);
}

/**
 * Read the client address from a forwarding chain, honouring only as many hops as the
 * deployment declared.
 *
 * `X-Forwarded-For` is client-supplied and append-only: each proxy appends what it saw, so
 * the rightmost entries are the ones added by infrastructure we control and the leftmost is
 * whatever the original caller claimed. Counting from the right by the declared hop count is
 * therefore the only reading that cannot be steered by the caller -- trusting the leftmost
 * entry (what `trust proxy: true` does) lets anyone mint a fresh identity per request.
 */
function addressFromChain(
  forwardedFor: string | undefined,
  remoteAddress: string | undefined,
  trustedHops: number,
): string | undefined {
  if (trustedHops <= 0 || !forwardedFor) return remoteAddress;

  // The full path is the forwarded entries followed by the socket peer, oldest first. The
  // rightmost is the hop we actually spoke to and is therefore the only one we know first
  // hand; each step left is one more claim we are choosing to believe. Skipping exactly the
  // declared number of trusted hops from the right lands on the caller, and no further --
  // anything left of that was appended by something we do not vouch for, including whatever
  // the original caller invented.
  const chain = [
    ...forwardedFor.split(',').map((s) => s.trim()).filter(Boolean),
    ...(remoteAddress ? [remoteAddress] : []),
  ];
  if (!chain.length) return remoteAddress;

  // A chain shorter than declared means fewer proxies than configured; stop at its start
  // rather than reading past it.
  const idx = Math.max(0, chain.length - 1 - trustedHops);
  return chain[idx] ?? remoteAddress;
}

export function callerKey(input: CallerKeyInput): CallerKey {
  const hops = Number.isFinite(input.trustedHops) ? Math.max(0, Math.trunc(input.trustedHops)) : 0;
  const proxyMismatch = hops === 0 && !!input.forwardedFor;

  // An authenticated caller is budgeted individually. This is the case that matters for the
  // deployments this platform targets: a ward office behind one NAT is a single address, so
  // address-keyed limiting punishes the busy office it exists to protect.
  if (input.credential) {
    return { key: `op:${fingerprint(input.credential)}`, source: 'operator', proxyMismatch };
  }

  const address = addressFromChain(input.forwardedFor, input.remoteAddress, hops);
  if (!address) {
    // No credential and no address. Counting these together is the safest reading: it is one
    // bucket for everything unattributable rather than an unlimited one.
    return { key: 'anon:unattributable', source: 'unattributable', proxyMismatch };
  }
  return { key: `ip:${address}`, source: 'address', proxyMismatch };
}
