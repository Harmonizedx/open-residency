import { JWK } from 'jose';
import { TrustedIssuer } from './vc-verifier';
import { StatusList } from './status-list';
import { VpTrustedIssuer, keyObjectFromJwk } from '../oid4vp/vp-verifier';

/**
 * Cross-issuer federation: turning a list of trusted peer issuers into the trust-map
 * entries the verifiers already understand.
 *
 * The verifiers were built multi-issuer from the start -- both trust maps are keyed by
 * issuer DID, and each entry carries an ARRAY of public keys so a peer can rotate without
 * invalidating credentials already in wallets. What was missing was the wiring that reads
 * peers from config and populates those maps; that is all this file is. No verification
 * logic changes: a federated credential is checked by exactly the same code that checks a
 * home-issued one, which is the property that makes federation trustworthy rather than a
 * second, weaker path.
 */

export interface FederatedIssuer {
  did: string;
  name?: string;
  /** Public signing keys, current first then retired. Rotation-safe by construction. */
  publicJwks: JWK[];
  statusListUrl?: string;
}

/** Trust-map entry (VC-JWT verifier) for a federated peer. */
export function federatedTrustedIssuer(peer: FederatedIssuer): TrustedIssuer {
  return { did: peer.did, publicJwks: peer.publicJwks, statusLists: {} };
}

/** Trust-map entry (OpenID4VP / Data Integrity verifier) for a federated peer. */
export function federatedVpTrustedIssuer(peer: FederatedIssuer): VpTrustedIssuer {
  return { did: peer.did, publicKeyObjects: peer.publicJwks.map(keyObjectFromJwk) };
}

/**
 * Add federated peers to the two trust maps, in place.
 *
 * Refuses to overwrite an issuer already present -- almost always the deployment's own
 * issuer DID, and silently replacing our own key with a peer-supplied one would be a
 * trust-store poisoning vector, not a convenience. A peer that collides with an existing
 * (self or earlier peer) DID is a configuration error and is reported, not merged.
 */
export function applyFederation(
  trust: Map<string, TrustedIssuer>,
  ldpTrust: Map<string, VpTrustedIssuer>,
  peers: FederatedIssuer[],
): void {
  for (const peer of peers) {
    if (trust.has(peer.did)) {
      throw new Error(
        `federation.trustedIssuers lists "${peer.did}", but that issuer DID is already ` +
          'trusted (it is this deployment\'s own issuer, or a duplicate peer). A federated ' +
          'peer must have a distinct DID.',
      );
    }
    trust.set(peer.did, federatedTrustedIssuer(peer));
    ldpTrust.set(peer.did, federatedVpTrustedIssuer(peer));
  }
}

/**
 * Extract a StatusList from a published BitstringStatusListCredential document.
 *
 * The published shape is the one this project serves at `/.well-known/status/{cc}.json`:
 * a credential whose `credentialSubject` carries `encodedList`. Peers running other
 * implementations publish the same W3C shape, which is the point of using it.
 *
 * Returns null rather than throwing on anything unrecognised. A peer that publishes
 * something we cannot parse must not take this deployment's boot down with it, and the
 * caller already treats "no list" as the safe state.
 */
export function statusListFromPublished(doc: unknown): StatusList | null {
  const subject = (doc as { credentialSubject?: unknown })?.credentialSubject;
  const encoded = (subject as { encodedList?: unknown })?.encodedList;
  if (typeof encoded !== 'string' || encoded.length === 0) return null;
  try {
    return StatusList.fromEncoded(encoded);
  } catch {
    return null;
  }
}

/** Outcome of one peer's status-list sync, for logging and for the operator to see. */
export interface PeerStatusSyncResult {
  did: string;
  name?: string;
  url?: string;
  status: 'synced' | 'not-configured' | 'unreachable' | 'unparseable';
  detail?: string;
}

/**
 * Fetch each federated peer's status list and cache it against their trust entry.
 *
 * Without this, `federatedTrustedIssuer` hands the verifier an empty `statusLists`, and the
 * peer's `statusListUrl` -- which is parsed, typed and documented -- is never read. Both
 * verification paths then go wrong, in opposite directions and for the same reason:
 *
 *   - the offline VC path reports `checkedRevocation: false` and returns valid, so a REVOKED
 *     peer credential is accepted;
 *   - the OpenID4VP path fails closed on exactly that flag, so a VALID peer credential is
 *     rejected as REVOCATION_UNCHECKABLE.
 *
 * The fetcher is injected rather than imported so this is exercisable without a network, and
 * so a deployment behind a proxy or an air gap can supply its own transport. A peer that
 * cannot be reached leaves its cache untouched: the OpenID4VP path keeps failing closed,
 * which is the correct posture for "I do not know whether this is revoked".
 */
export async function syncFederatedStatusLists(
  trust: Map<string, TrustedIssuer>,
  peers: FederatedIssuer[],
  fetchJson: (url: string) => Promise<unknown>,
): Promise<PeerStatusSyncResult[]> {
  const results: PeerStatusSyncResult[] = [];
  for (const peer of peers) {
    const base = { did: peer.did, name: peer.name, url: peer.statusListUrl };
    if (!peer.statusListUrl) {
      results.push({ ...base, status: 'not-configured' });
      continue;
    }
    let doc: unknown;
    try {
      doc = await fetchJson(peer.statusListUrl);
    } catch (e) {
      results.push({ ...base, status: 'unreachable', detail: (e as Error).message });
      continue;
    }
    const list = statusListFromPublished(doc);
    if (!list) {
      results.push({ ...base, status: 'unparseable' });
      continue;
    }
    const entry = trust.get(peer.did);
    if (!entry) {
      results.push({ ...base, status: 'unreachable', detail: 'peer not in trust map' });
      continue;
    }
    // Keyed by the peer's published URL, because that is the value that appears in the
    // credential's `credentialStatus.statusListCredential` and is what the verifier looks up.
    entry.statusLists = { ...(entry.statusLists ?? {}), [peer.statusListUrl]: list };
    results.push({ ...base, status: 'synced' });
  }
  return results;
}
