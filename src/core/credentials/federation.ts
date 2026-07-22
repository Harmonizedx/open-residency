import { JWK } from 'jose';
import { TrustedIssuer } from './vc-verifier';
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
