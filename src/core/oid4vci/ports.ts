/**
 * Persistence for the short-lived state an OpenID4VCI issuance needs: the credential
 * offer, the one-time pre-authorized code, and the nonces a wallet must sign over.
 *
 * All of it is short-lived (minutes), but none of it can be kept in process memory in a
 * real deployment: the Kubernetes manifests run multiple replicas behind a load
 * balancer, and a wallet's token request will not necessarily land on the same pod that
 * created the offer. Hence a port, with a Prisma-backed implementation in production and
 * the in-memory one below for tests and single-node pilots.
 */

export interface CredentialOfferRecord {
  id: string;
  /** Hashed. The raw code is shown once, in the QR, and never stored. */
  preAuthorizedCodeHash: string;
  /** Hashed, when the offer requires a transaction code (PIN). */
  txCodeHash?: string;
  residentId: string;
  countryCode: string;
  credentialConfigurationIds: string[];
  expiresAt: string;
  /** Set once the code has been exchanged for an access token. */
  redeemedAt?: string;
  /** Wrong-PIN counter, so a 4-digit tx_code cannot be brute-forced. */
  failedAttempts: number;
  createdAt: string;
}

export interface NonceRecord {
  /** Hashed, so a database read cannot be turned into a forged proof. */
  nonceHash: string;
  expiresAt: string;
}

export interface Oid4vciStore {
  saveOffer(offer: CredentialOfferRecord): Promise<void>;
  findOfferById(id: string): Promise<CredentialOfferRecord | null>;
  findOfferByCodeHash(codeHash: string): Promise<CredentialOfferRecord | null>;
  updateOffer(offer: CredentialOfferRecord): Promise<void>;

  saveNonce(nonce: NonceRecord): Promise<void>;
  /**
   * Atomically consume a nonce. MUST return true at most once for a given nonce, even
   * under concurrent calls -- this is the replay defence, so a compare-then-delete that
   * races is not good enough.
   */
  consumeNonce(nonceHash: string): Promise<boolean>;
}

/** In-memory implementation, for the smoke test and single-node pilots. */
export class InMemoryOid4vciStore implements Oid4vciStore {
  private offers = new Map<string, CredentialOfferRecord>();
  private byCodeHash = new Map<string, string>();
  private nonces = new Map<string, NonceRecord>();

  async saveOffer(offer: CredentialOfferRecord): Promise<void> {
    this.offers.set(offer.id, offer);
    this.byCodeHash.set(offer.preAuthorizedCodeHash, offer.id);
  }
  async findOfferById(id: string): Promise<CredentialOfferRecord | null> {
    return this.offers.get(id) ?? null;
  }
  async findOfferByCodeHash(codeHash: string): Promise<CredentialOfferRecord | null> {
    const id = this.byCodeHash.get(codeHash);
    return id ? (this.offers.get(id) ?? null) : null;
  }
  async updateOffer(offer: CredentialOfferRecord): Promise<void> {
    this.offers.set(offer.id, offer);
  }

  async saveNonce(nonce: NonceRecord): Promise<void> {
    this.nonces.set(nonce.nonceHash, nonce);
  }
  async consumeNonce(nonceHash: string): Promise<boolean> {
    const found = this.nonces.get(nonceHash);
    if (!found) return false;
    // Single-threaded event loop: delete-then-check is atomic here.
    this.nonces.delete(nonceHash);
    return new Date(found.expiresAt).getTime() > Date.now();
  }
}
