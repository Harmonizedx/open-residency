// SPDX-License-Identifier: Apache-2.0
import { JWK } from 'jose';
import { TrustedIssuer } from './vc-verifier';
import { StatusList } from './status-list';
import { LdpCredential, LdpIssuer } from './ldp-issuer';
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
  /**
   * Accept this peer's status list even though it carries no verifiable proof.
   *
   * Off by default, and it should stay off. A status list is the artifact that says which of
   * a peer's credentials have been revoked; cached unsigned, it is authenticated only by TLS
   * to whatever host answered, so anyone able to spoof that host can serve a list that
   * silently UN-REVOKES credentials this deployment would otherwise refuse.
   *
   * The escape hatch exists for one situation: a peer still running a build that publishes
   * bare JSON. Turning it on is a deliberate, per-peer, visible-in-config decision to trust
   * transport instead of a signature — never a default, and never global.
   */
  allowUnsignedStatusList?: boolean;
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
  status: 'synced' | 'not-configured' | 'unreachable' | 'unparseable' | 'unsigned' | 'untrusted';
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
    // Authenticate the document BEFORE parsing anything out of it.
    //
    // A revocation list is the one artifact where believing a forgery fails in the dangerous
    // direction: a forged list does not grant access it should not, it RESTORES access that
    // was deliberately taken away. Signature first, bitstring second.
    const authenticity = await verifyPublishedStatusList(doc, peer);
    if (authenticity !== 'ok') {
      results.push({ ...base, status: authenticity, detail: statusListRejectionDetail(authenticity) });
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

/**
 * Is this published status list genuinely the peer's?
 *
 * Three checks, in the order that fails cheapest first:
 *
 *   1. A proof must be present. Absent one, the artifact is authenticated only by TLS to
 *      whatever host answered -- and an attacker who can serve the URL simply omits the
 *      proof. Rejecting unsigned lists is what makes the signature meaningful; accepting
 *      them makes it decorative.
 *   2. The credential must name the peer as issuer. Otherwise a peer could relay a list
 *      signed by some other party.
 *   3. The proof must verify against the keys WE hold for that peer, not against a key the
 *      document supplies. A document that carries its own trust anchor proves nothing.
 *
 * Verification uses the same `LdpIssuer.verify` that checks a peer's Data Integrity
 * credentials, against the same rotation-tolerant key list, so a peer rotating keys does not
 * silently stop syncing.
 */
async function verifyPublishedStatusList(
  doc: unknown,
  peer: FederatedIssuer,
): Promise<'ok' | 'unsigned' | 'untrusted'> {
  const credential = doc as LdpCredential & { issuer?: unknown };
  const hasProof = !!(credential && typeof credential === 'object' && credential.proof);

  if (!hasProof) return peer.allowUnsignedStatusList ? 'ok' : 'unsigned';

  const issuer = typeof credential.issuer === 'string' ? credential.issuer : undefined;
  if (issuer && issuer !== peer.did) return 'untrusted';

  const keys = peer.publicJwks.map(keyObjectFromJwk);
  try {
    return (await LdpIssuer.verify(credential, keys)) ? 'ok' : 'untrusted';
  } catch {
    return 'untrusted';
  }
}

function statusListRejectionDetail(status: 'unsigned' | 'untrusted'): string {
  return status === 'unsigned'
    ? 'the published list carries no proof; set allowUnsignedStatusList on this peer only if ' +
        'you accept transport-only authentication for its revocations'
    : 'the proof did not verify against the keys held for this peer';
}
