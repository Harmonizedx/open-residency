/**
 * State for an in-flight presentation request.
 *
 * A request is created by a relying party, answered by a wallet on a different
 * connection (and, in a real deployment, very likely a different pod), and then polled
 * for by the relying party. So this cannot live in process memory.
 */

export interface PresentationRequestRecord {
  id: string;
  /** The nonce the wallet must sign over. Single-use; this is the replay defence. */
  nonce: string;
  /** Who is asking. Presentations are made out to this audience and no other. */
  clientId: string;
  /** What the relying party wants to know, for the consent screen and the audit log. */
  purpose: string;
  /** Optional: the relying party's own reference, echoed back to it. */
  reference?: string;
  status: 'pending' | 'fulfilled' | 'failed';
  /** The verification outcome, once a wallet has responded. */
  outcome?: Record<string, unknown>;
  expiresAt: string;
  createdAt: string;
}

export interface Oid4vpStore {
  saveRequest(request: PresentationRequestRecord): Promise<void>;
  findRequest(id: string): Promise<PresentationRequestRecord | null>;
  /**
   * Record the outcome, but only if the request is still `pending`.
   *
   * MUST be atomic and MUST return false if the request has already been answered. This
   * is what makes a presentation single-use: without it, a captured vp_token could be
   * posted a second time and overwrite a verdict, or be accepted twice.
   */
  completeRequest(
    id: string,
    status: 'fulfilled' | 'failed',
    outcome: Record<string, unknown>,
  ): Promise<boolean>;
}

/** In-memory implementation, for the smoke test and single-node pilots. */
export class InMemoryOid4vpStore implements Oid4vpStore {
  private requests = new Map<string, PresentationRequestRecord>();

  async saveRequest(request: PresentationRequestRecord): Promise<void> {
    this.requests.set(request.id, request);
  }
  async findRequest(id: string): Promise<PresentationRequestRecord | null> {
    return this.requests.get(id) ?? null;
  }
  async completeRequest(
    id: string,
    status: 'fulfilled' | 'failed',
    outcome: Record<string, unknown>,
  ): Promise<boolean> {
    const found = this.requests.get(id);
    // Single-threaded event loop, so check-then-set is atomic here.
    if (!found || found.status !== 'pending') return false;
    this.requests.set(id, { ...found, status, outcome });
    return true;
  }
}
