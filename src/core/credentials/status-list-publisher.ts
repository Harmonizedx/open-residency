// SPDX-License-Identifier: Apache-2.0
import { StatusList, unsignedStatusListCredential } from './status-list';
import { LdpIssuer, LdpCredential } from './ldp-issuer';

/**
 * Signs the published status list, and caches the signed credential so a frequently polled,
 * unauthenticated endpoint does not re-invoke the issuer key on every request.
 *
 * The problem this exists to prevent: `GET /.well-known/status/:file` is public and
 * unauthenticated, and signing runs JSON-LD canonicalization plus an issuer-key signature.
 * In production that key is held in an HSM/KMS, so signing on every request lets anyone
 * drive unbounded remote sign operations against the very backend that also issues
 * credentials -- a cost and denial-of-service vector, not just a slow endpoint.
 *
 * The status bitstring only changes on revocation, so the signed artifact is re-minted only
 * when its `encodedList` changes. Until then the exact same document is returned -- same
 * `validFrom`, same proof -- which is both cheap to serve and stable for verifiers caching
 * it. Invalidation is keyed on the encoded content itself, so it is correct without having
 * to observe revocation events.
 */
export class StatusListPublisher {
  private cache = new Map<string, { encodedList: string; credential: LdpCredential }>();

  constructor(private ldpIssuer: LdpIssuer) {}

  async publish(
    id: string,
    issuerDid: string,
    list: StatusList,
    purpose: 'revocation' | 'suspension' = 'revocation',
  ): Promise<LdpCredential> {
    const encodedList = list.encode();
    // Neither a DID nor a URL contains a space, so it is a safe delimiter between the two.
    // The purpose joins the key because the same bitstring published under two purposes is
    // two different credentials, and returning one for the other would tell a verifier that
    // a suspended credential is revoked.
    const cacheKey = `${issuerDid} ${id} ${purpose}`;
    const hit = this.cache.get(cacheKey);
    // Content-addressed cache: an unchanged list returns the already-signed credential,
    // so no canonicalization and no issuer-key signature happen on a plain poll.
    if (hit && hit.encodedList === encodedList) return hit.credential;

    const unsigned = unsignedStatusListCredential({ id, issuerDid, list, purpose });
    const credential = await this.ldpIssuer.sign(unsigned, issuerDid);
    this.cache.set(cacheKey, { encodedList, credential });
    return credential;
  }
}
