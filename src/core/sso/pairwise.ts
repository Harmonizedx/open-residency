import { createHmac } from 'node:crypto';

/**
 * Pairwise subject identifiers (OpenID Connect Core §8.1).
 *
 * A public `sub` is the same string at every relying party, so two services that hold the
 * same citizen's records can join them on it. In a government context that is the whole
 * concern: Health and Tax are meant to be able to authenticate the same person without
 * being able to assemble a shared dossier on them. A pairwise identifier gives each
 * service a stable handle for its own users that means nothing anywhere else.
 *
 * HMAC-SHA256 under the deployment pepper, truncated to 40 hex characters -- the same
 * construction and the same length the foundational subjectRef uses (see
 * foundational/util.ts), so there is one tokenization scheme in this codebase rather than
 * two that have to be reasoned about separately.
 *
 * The pepper is what makes this safe. Without it the derivation is public and anyone
 * could recompute every service's view of a citizen from a residency id; with it, a
 * relying party cannot invert its own identifiers, and cannot predict another party's.
 * Rotating the pepper re-pseudonymises everyone -- every RP sees all its users as new --
 * which is why it is a long-lived secret, and why the same warning applies here as to
 * subject references.
 */
export function pairwiseSubject(pepper: string, clientId: string, residentId: string): string {
  // clientId is length-prefixed rather than merely concatenated: without it, client "ab"
  // with resident "cd" and client "a" with resident "bcd" would collide onto one subject.
  return createHmac('sha256', pepper)
    .update(`${clientId.length}:${clientId}:${residentId}`)
    .digest('hex')
    .slice(0, 40);
}
