// SPDX-License-Identifier: Apache-2.0

/**
 * Who a rate limit counts against (ADR-0013).
 *
 * Framework-free and pure: the delivery layer reads the request, this decides. That keeps the
 * decision testable without booting an application, which matters because the defect this
 * replaces was invisible precisely because nothing exercised it.
 *
 * NOTHING THE CALLER CONTROLS MAY REACH THE KEY. That is the whole property. A key derived
 * from anything a caller can vary -- a header they set, a credential nobody has verified --
 * hands them a fresh, empty budget on every request, which is not a weaker limit but no limit
 * at all. `X-Forwarded-For` is read only as far as the deployment says it trusts, and a
 * presented credential is not read here: the rate limiter runs before authentication, so at
 * this point a credential is an unverified string. See the note on per-operator budgets in
 * ADR-0013.
 */
export interface CallerKeyInput {
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
  source: 'address' | 'unattributable';
  /**
   * The request carries a forwarding header while the deployment declares no proxy, so the
   * address being counted is a proxy's rather than a caller's. The limit is not doing what it
   * appears to do, and the caller of this function is expected to say so out loud.
   */
  proxyMismatch: boolean;
}

/**
 * Read the client address from a forwarding chain, honouring only as many hops as the
 * deployment declared.
 *
 * The full path is the forwarded entries followed by the socket peer, oldest first. The
 * rightmost is the hop we actually spoke to and is the only one we know first hand; each step
 * left is one more claim we are choosing to believe. Skipping exactly the declared number of
 * trusted hops from the right lands on the caller and no further -- anything left of that was
 * appended by something we do not vouch for, including whatever the original caller invented.
 */
function addressFromChain(
  forwardedFor: string | undefined,
  remoteAddress: string | undefined,
  trustedHops: number,
): string | undefined {
  if (trustedHops <= 0 || !forwardedFor) return remoteAddress;

  const chain = [
    ...forwardedFor.split(',').map((s) => s.trim()).filter(Boolean),
    ...(remoteAddress ? [remoteAddress] : []),
  ];
  const idx = chain.length - 1 - trustedHops;

  // Fewer proxies than declared. Clamping to index 0 would read the LEFTMOST entry, which is
  // whatever the caller sent -- so a deployment that declares two hops and receives a request
  // through one would let that caller choose their own bucket. Fall back to the socket peer,
  // which is always true even when it is less useful.
  if (idx < 0) return remoteAddress;
  return chain[idx] ?? remoteAddress;
}

export function callerKey(input: CallerKeyInput): CallerKey {
  const hops = Number.isFinite(input.trustedHops) ? Math.max(0, Math.trunc(input.trustedHops)) : 0;
  const proxyMismatch = hops === 0 && !!input.forwardedFor;

  const address = addressFromChain(input.forwardedFor, input.remoteAddress, hops);
  if (!address) {
    // No address at all. Counting these together is the safest reading: one bucket for
    // everything unattributable rather than an unlimited one.
    return { key: 'anon:unattributable', source: 'unattributable', proxyMismatch };
  }
  return { key: `ip:${address}`, source: 'address', proxyMismatch };
}
