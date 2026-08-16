// SPDX-License-Identifier: Apache-2.0
import axios from 'axios';

/**
 * Retry with backoff for foundational gateway calls.
 *
 * A national ID gateway is somebody else's server, reached over somebody else's network,
 * from an enrolment desk that may be on a congested rural link. Transient failure is the
 * normal case, not the exceptional one. Without a retry a single dropped packet refuses a
 * citizen's enrolment outright, and the desk's only recourse is to key the whole
 * application in again.
 *
 * What is retried is deliberately narrow, because the failure modes are not alike:
 *
 *   - **A transport failure or timeout** — no response arrived. Retry: nothing at the far
 *     end has necessarily happened, and the next attempt may land.
 *   - **429 Too Many Requests** — the gateway is explicitly asking us to slow down. Retry,
 *     honouring `Retry-After` when it sends one.
 *   - **5xx** — the far end is broken, and says so. Retry.
 *   - **Any other 4xx** — the gateway understood us and said no. A malformed request or an
 *     unknown NIN is not going to become valid on the second attempt; retrying spends a
 *     paid API call to receive the same answer, and on a rate-limited contract it spends
 *     the budget of the citizens queued behind this one. Do not retry.
 *
 * A verification that returns cleanly with "no match" never reaches here at all: that is a
 * successful call with a negative result, and the adapters map it without raising.
 */

export interface RetryPolicy {
  /** Total attempts including the first. 1 disables retrying. */
  attempts: number;
  /** Base for the exponential backoff, in milliseconds. */
  baseDelayMs: number;
  /** Ceiling for any single backoff wait, in milliseconds. */
  maxDelayMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  // Three attempts covers the overwhelmingly common case (one blip) without leaving an
  // applicant standing at a desk: with the delays below the worst case adds well under two
  // seconds before the call is reported as failed.
  attempts: 3,
  baseDelayMs: 200,
  maxDelayMs: 2000,
};

export function resolveRetryPolicy(configured?: Partial<RetryPolicy>): RetryPolicy {
  const p = { ...DEFAULT_RETRY_POLICY, ...(configured ?? {}) };
  return {
    attempts: Math.max(1, Math.floor(p.attempts)),
    baseDelayMs: Math.max(0, p.baseDelayMs),
    maxDelayMs: Math.max(0, p.maxDelayMs),
  };
}

/** Is this failure worth a second attempt? See the table above for why each case. */
export function isRetryable(err: unknown): boolean {
  if (!axios.isAxiosError(err)) return false;
  const status = err.response?.status;
  // No response at all: DNS, connection reset, or the client-side timeout fired.
  if (status === undefined) return true;
  if (status === 429) return true;
  return status >= 500 && status <= 599;
}

/**
 * How long the gateway asked us to wait, if it said so.
 *
 * `Retry-After` is either a delay in seconds or an HTTP date. Both are honoured: ignoring
 * it and backing off on our own schedule is how a client that is already being rate
 * limited earns a longer ban.
 */
export function retryAfterMs(err: unknown, now: number = Date.now()): number | undefined {
  if (!axios.isAxiosError(err)) return undefined;
  const raw = err.response?.headers?.['retry-after'];
  if (raw == null) return undefined;
  const header = String(raw).trim();
  if (/^\d+$/.test(header)) return Number(header) * 1000;
  const at = Date.parse(header);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, at - now);
}

/**
 * Full-jitter exponential backoff.
 *
 * Jitter matters more than the exponent here. When a gateway comes back after an outage,
 * every desk that was retrying against it is holding a synchronised timer; without jitter
 * they all return in the same instant and knock it straight back over. Randomising across
 * the whole window spreads that return out.
 */
export function backoffMs(
  attempt: number,
  policy: RetryPolicy,
  random: () => number = Math.random,
): number {
  const window = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** (attempt - 1));
  return Math.floor(random() * window);
}

export interface RetryHooks {
  /** Called before each wait, for logging and for tests to observe the schedule. */
  onRetry?: (info: { attempt: number; delayMs: number; error: unknown }) => void;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
}

/**
 * Run `call`, retrying transient failures per `policy`.
 *
 * Rethrows the LAST error once attempts are exhausted, so the adapter's existing error
 * mapping (`PROVIDER_HTTP_*` / `PROVIDER_UNREACHABLE`) still describes what actually went
 * wrong. A non-retryable failure is rethrown immediately, without waiting.
 */
export async function withRetry<T>(
  call: () => Promise<T>,
  policy: RetryPolicy,
  hooks: RetryHooks = {},
): Promise<T> {
  const sleep = hooks.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const random = hooks.random ?? Math.random;
  const now = hooks.now ?? Date.now;

  let lastError: unknown;
  for (let attempt = 1; attempt <= policy.attempts; attempt++) {
    try {
      return await call();
    } catch (err) {
      lastError = err;
      if (attempt === policy.attempts || !isRetryable(err)) throw err;
      // A server-supplied Retry-After wins over our own schedule, but is still capped:
      // an enrolment desk cannot block for the minutes some gateways ask for.
      const asked = retryAfterMs(err, now());
      const delayMs =
        asked !== undefined
          ? Math.min(asked, policy.maxDelayMs)
          : backoffMs(attempt, policy, random);
      hooks.onRetry?.({ attempt, delayMs, error: err });
      await sleep(delayMs);
    }
  }
  throw lastError;
}