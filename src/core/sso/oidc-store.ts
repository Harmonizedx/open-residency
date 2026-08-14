// SPDX-License-Identifier: Apache-2.0

/**
 * Storage for the OpenID Connect provider's own state -- sessions, interactions,
 * authorization codes, access and refresh tokens, grants.
 *
 * `oidc-provider` falls back to a development adapter that holds all of this in a Map
 * whenever `adapter` is left unset. That is single-process storage, and the sign-in flow
 * spans more than one process the moment a deployment runs more than one replica: the
 * authorization code is minted on the citizen's redirect and redeemed by the relying
 * party's backend on a separate connection, which load-balances independently.
 *
 * The resulting failure is intermittent rather than clean. The session cookie still
 * verifies on the second replica -- its signing key is shared through OIDC_COOKIE_SECRET
 * -- so what the citizen sees is not an error but a silent bounce back to the login page,
 * or an `invalid_grant` the relying party cannot explain. Restarts lose every session too,
 * which is why the fourteen-day `Session` and `Grant` TTLs only mean anything once this
 * port is backed by a database.
 *
 * `PresentationRequest` in the Prisma schema already records this reasoning for OpenID4VP:
 * interactions that will not land on the same replica need a table, not a map.
 */

/** One row of provider state, keyed by the model name and id oidc-provider assigns. */
export interface OidcStoredItem {
  /** oidc-provider model: 'Session', 'AuthorizationCode', 'AccessToken', 'Grant', ... */
  name: string;
  id: string;
  payload: Record<string, unknown>;
  /** Set on tokens so revoking a grant can cascade to everything issued under it. */
  grantId?: string | null;
  /** Session lookup key, distinct from the id. */
  uid?: string | null;
  /** Device-flow user code. */
  userCode?: string | null;
  /** Absent means "never expires" -- oidc-provider omits expiresIn for some models. */
  expiresAt?: Date | null;
  /** When a single-use artefact (an authorization code) was redeemed. */
  consumedAt?: Date | null;
}

/**
 * The persistence port. Every read takes `now` explicitly so expiry is decided by the
 * caller's clock rather than the database's, which keeps the in-memory and Prisma
 * implementations answerable to the same test.
 */
export interface OidcStore {
  upsert(item: OidcStoredItem): Promise<void>;
  find(name: string, id: string, now: Date): Promise<OidcStoredItem | null>;
  findByUid(name: string, uid: string, now: Date): Promise<OidcStoredItem | null>;
  findByUserCode(name: string, userCode: string, now: Date): Promise<OidcStoredItem | null>;
  consume(name: string, id: string, at: Date): Promise<void>;
  destroy(name: string, id: string): Promise<void>;
  revokeByGrantId(name: string, grantId: string): Promise<void>;
  /**
   * Delete everything already past its expiry, returning how many rows went.
   *
   * Expired rows are never *returned* -- `find` filters them -- but without this they
   * accumulate forever. At state scale that is the busiest table in the deployment.
   */
  purgeExpired(now: Date): Promise<number>;
}

/** In-memory implementation, for the smoke test and single-node pilots. */
export class InMemoryOidcStore implements OidcStore {
  private items = new Map<string, OidcStoredItem>();

  private static key(name: string, id: string): string {
    return `${name}:${id}`;
  }

  private live(item: OidcStoredItem | undefined, now: Date): OidcStoredItem | null {
    if (!item) return null;
    if (item.expiresAt && item.expiresAt.getTime() <= now.getTime()) return null;
    return item;
  }

  async upsert(item: OidcStoredItem): Promise<void> {
    const key = InMemoryOidcStore.key(item.name, item.id);
    // oidc-provider upserts an existing id to extend or amend it; a re-upsert must not
    // silently clear the consumed marker that makes an authorization code single-use.
    const previous = this.items.get(key);
    this.items.set(key, { ...item, consumedAt: item.consumedAt ?? previous?.consumedAt ?? null });
  }

  async find(name: string, id: string, now: Date): Promise<OidcStoredItem | null> {
    return this.live(this.items.get(InMemoryOidcStore.key(name, id)), now);
  }

  async findByUid(name: string, uid: string, now: Date): Promise<OidcStoredItem | null> {
    for (const item of this.items.values()) {
      if (item.name === name && item.uid === uid) return this.live(item, now);
    }
    return null;
  }

  async findByUserCode(name: string, userCode: string, now: Date): Promise<OidcStoredItem | null> {
    for (const item of this.items.values()) {
      if (item.name === name && item.userCode === userCode) return this.live(item, now);
    }
    return null;
  }

  async consume(name: string, id: string, at: Date): Promise<void> {
    const item = this.items.get(InMemoryOidcStore.key(name, id));
    if (item) item.consumedAt = at;
  }

  async destroy(name: string, id: string): Promise<void> {
    this.items.delete(InMemoryOidcStore.key(name, id));
  }

  async revokeByGrantId(name: string, grantId: string): Promise<void> {
    for (const [key, item] of [...this.items.entries()]) {
      if (item.name === name && item.grantId === grantId) this.items.delete(key);
    }
  }

  async purgeExpired(now: Date): Promise<number> {
    let removed = 0;
    for (const [key, item] of [...this.items.entries()]) {
      if (item.expiresAt && item.expiresAt.getTime() <= now.getTime()) {
        this.items.delete(key);
        removed += 1;
      }
    }
    return removed;
  }
}

/**
 * The shape `oidc-provider` calls. Declared structurally rather than imported so this
 * file stays free of the dependency -- `src/core` carries no delivery-layer imports, and
 * the adapter contract is small enough to state.
 */
export interface OidcAdapterLike {
  upsert(id: string, payload: Record<string, unknown>, expiresIn?: number): Promise<void>;
  find(id: string): Promise<Record<string, unknown> | undefined>;
  findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined>;
  findByUid(uid: string): Promise<Record<string, unknown> | undefined>;
  consume(id: string): Promise<void>;
  destroy(id: string): Promise<void>;
  revokeByGrantId(grantId: string): Promise<void>;
}

/** oidc-provider reads consumption off the payload, in epoch seconds. */
function epochSeconds(at: Date): number {
  return Math.floor(at.getTime() / 1000);
}

/**
 * Build the `adapter` factory oidc-provider expects: it constructs one per model name and
 * uses it for every read and write of that model's state.
 *
 * `clock` is injectable so a test can age a token out without sleeping.
 */
export function createOidcAdapterFactory(
  store: OidcStore,
  clock: () => Date = () => new Date(),
): (name: string) => OidcAdapterLike {
  return (name: string): OidcAdapterLike => ({
    async upsert(id, payload, expiresIn) {
      await store.upsert({
        name,
        id,
        payload,
        // These three are lifted out of the payload into columns purely so they can be
        // indexed; the payload remains the record of truth.
        grantId: typeof payload.grantId === 'string' ? payload.grantId : null,
        uid: typeof payload.uid === 'string' ? payload.uid : null,
        userCode: typeof payload.userCode === 'string' ? payload.userCode : null,
        expiresAt: expiresIn === undefined ? null : new Date(clock().getTime() + expiresIn * 1000),
      });
    },

    async find(id) {
      return materialize(await store.find(name, id, clock()));
    },

    async findByUid(uid) {
      return materialize(await store.findByUid(name, uid, clock()));
    },

    async findByUserCode(userCode) {
      return materialize(await store.findByUserCode(name, userCode, clock()));
    },

    async consume(id) {
      await store.consume(name, id, clock());
    },

    async destroy(id) {
      await store.destroy(name, id);
    },

    async revokeByGrantId(grantId) {
      await store.revokeByGrantId(name, grantId);
    },
  });
}

/**
 * Re-attach `consumed` to the payload on the way out.
 *
 * oidc-provider decides whether an authorization code has already been redeemed by
 * reading `consumed` off what `find` returns, so a store that records consumption in a
 * column has to put it back. Without this, replaying a code succeeds -- which is the
 * attack the single-use rule exists to stop.
 */
function materialize(item: OidcStoredItem | null): Record<string, unknown> | undefined {
  if (!item) return undefined;
  if (!item.consumedAt) return item.payload;
  return { ...item.payload, consumed: epochSeconds(item.consumedAt) };
}