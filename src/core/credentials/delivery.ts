// SPDX-License-Identifier: Apache-2.0

/**
 * Credential delivery: the step between "issued" and "in the holder's hands".
 *
 * ## Why this exists
 *
 * Every registration programme that has stalled in this project's first country stalled here,
 * not at enrolment. Lagos enrolled millions and validated a fifth; cards sat uncollected in
 * their hundreds of thousands. Kaduna is running a randomised trial on how to get cards into
 * people's hands because distribution, not interest, is the binding constraint. The national
 * identity programme itself reports that a printed slip does not mean a collected one and
 * that collection cannot be tracked. A register that cannot say whether the thing it issued
 * ever reached the person has no way to see the failure that matters most.
 *
 * So delivery is recorded as its own event stream, beside the record rather than on it: which
 * channel carried the credential, what happened, when, and on whose say-so. A deployment that
 * hands over at the desk in one step loses nothing -- the default records nothing and the
 * credential is ACTIVE on issue, exactly as before. A deployment with a collection step sets
 * `credential.activateOn: first_delivery`, and the credential is ISSUED until a delivery or
 * collection is recorded, which is the state the lifecycle vocabulary always reserved for this.
 *
 * ## What this deliberately does NOT do
 *
 * It does not make delivery a precondition of verification. An ISSUED credential verifies: it
 * exists, it is not revoked, and withholding it from a verifier because the register has not
 * yet heard that it was collected would punish the holder for the register's bookkeeping. The
 * status is for the register and its statistics, not for the service counter.
 *
 * It does not record a delivery from any unauthenticated path. The public QR renderer, for
 * one, could be called by anyone with a credential string; a delivery recorded from it would
 * be a delivery recorded by nobody. Deliveries are recorded by an authenticated operator, or
 * by the wallet protocol when a holder's own key has just collected the credential.
 */

/**
 * How a credential reached, or was meant to reach, the holder.
 *
 * `wallet_oid4vci` -- the holder's wallet pulled it over OpenID4VCI, proving possession of a
 * key. Recorded by the protocol itself as `collected`.
 * `qr_print` -- rendered as a QR and printed or shown for the holder to carry.
 * `paper` -- a printed document carrying the credential or its QR.
 * `sms_link` -- a link sent by SMS, for the holder to collect through.
 * `ussd_collect` -- collected through a USSD menu on a feature phone.
 * `agent_handover` -- handed over in person by an enrolment agent, at a desk or door to door.
 */
export type DeliveryChannel =
  | 'wallet_oid4vci'
  | 'qr_print'
  | 'paper'
  | 'sms_link'
  | 'ussd_collect'
  | 'agent_handover';

export const DELIVERY_CHANNELS: readonly DeliveryChannel[] = [
  'wallet_oid4vci',
  'qr_print',
  'paper',
  'sms_link',
  'agent_handover',
  'ussd_collect',
];

/**
 * What happened on that channel.
 *
 * `pending` -- dispatched or scheduled, outcome not yet known (an SMS sent, a card printed).
 * `delivered` -- the register has grounds to say it reached the holder (handed over, shown).
 * `collected` -- the holder came and took it (a wallet pulled it; a person collected a card).
 * `failed` -- the attempt did not reach the holder; `failureReason` says why, when known.
 *
 * `delivered` and `collected` both count as delivery for activation. They are kept distinct
 * because the programmes this is for distinguish them: a door-to-door handover and a
 * central-pickup collection are different operations with different costs and failure modes,
 * and conflating them would hide exactly the comparison those programmes are running.
 */
export type DeliveryStatus = 'pending' | 'delivered' | 'collected' | 'failed';

export const DELIVERY_STATUSES: readonly DeliveryStatus[] = ['pending', 'delivered', 'collected', 'failed'];

/** Does this status mean the credential is in the holder's hands? */
export function isDeliveredStatus(status: DeliveryStatus): boolean {
  return status === 'delivered' || status === 'collected';
}

export interface CredentialDeliveryEvent {
  id: string;
  residentId: string;
  countryCode: string;
  /** The credential this concerns, when known. Absent for channels that carry the record id only. */
  credentialId?: string;
  channel: DeliveryChannel;
  status: DeliveryStatus;
  /** ISO instant the event happened. */
  at: string;
  /** Who recorded it: an operator actor, or `wallet` for the protocol path. */
  by?: string;
  /** For `failed`: what went wrong, in the channel's own terms. */
  failureReason?: string;
  /** An opaque reference: a batch id, a courier receipt, a message id, a collection slip. */
  evidenceRef?: string;
}

/** Counts by channel and status, for the statistics surface. Non-PII by construction. */
export type DeliveryCounts = Partial<Record<DeliveryChannel, Partial<Record<DeliveryStatus, number>>>>;

export interface DeliveryStore {
  append(event: CredentialDeliveryEvent): Promise<void>;
  /** Every event for a resident, oldest first. */
  listByResident(residentId: string): Promise<CredentialDeliveryEvent[]>;
  /** Counts of events by channel and status, optionally for one country. */
  counts(countryCode?: string): Promise<DeliveryCounts>;
}

/** Fold events into counts. Shared by the in-memory store and the statistics surface. */
export function countDeliveries(events: Iterable<CredentialDeliveryEvent>): DeliveryCounts {
  const out: DeliveryCounts = {};
  for (const e of events) {
    const byStatus = (out[e.channel] ??= {});
    byStatus[e.status] = (byStatus[e.status] ?? 0) + 1;
  }
  return out;
}

/** The latest event per resident decides whether they have been delivered to. */
export function latestDelivery(events: CredentialDeliveryEvent[]): CredentialDeliveryEvent | undefined {
  let best: CredentialDeliveryEvent | undefined;
  for (const e of events) if (!best || e.at > best.at) best = e;
  return best;
}

export class InMemoryDeliveryStore implements DeliveryStore {
  private events: CredentialDeliveryEvent[] = [];

  async append(event: CredentialDeliveryEvent): Promise<void> {
    this.events.push({ ...event });
  }

  async listByResident(residentId: string): Promise<CredentialDeliveryEvent[]> {
    return this.events.filter((e) => e.residentId === residentId).sort((a, b) => a.at.localeCompare(b.at));
  }

  async counts(countryCode?: string): Promise<DeliveryCounts> {
    const cc = countryCode?.toUpperCase();
    return countDeliveries(cc ? this.events.filter((e) => e.countryCode.toUpperCase() === cc) : this.events);
  }
}
