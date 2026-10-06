// SPDX-License-Identifier: Apache-2.0

/**
 * A resident's view of who has looked at their record.
 *
 * ## Why this exists
 *
 * The audit log records every operator read, every verification of a credential, every
 * presentation to a relying party and every wallet collection, in a hash-chained trail that an
 * auditor can inspect. The person whose record it is could not. GovStack's Digital Registries
 * requirements ask that every read be logged AND that the data owner can view the access events;
 * the DPG Standard's privacy indicator asks how adverse impacts of distribution are prevented;
 * the ID4D Practitioner's Guide names "a person can see who accessed their record" as the
 * concrete form of agency over one's own data. This module is the register's answer.
 *
 * ## What this deliberately does NOT do
 *
 * It does not show the resident WHICH operator looked. Staff have privacy too, and a register
 * that handed a citizen a named list of clerks would create a new harm while curing an old one.
 * The resident sees the KIND of actor (an operator at the agency, a verifier, a relying party by
 * its registered name, a wallet) and the moment; each entry carries the audit event's id, so a
 * complaint to the agency or the regulator can be investigated against the full trail. For a
 * relying party the registered client identifier IS shown, because the resident consented to
 * that service and has the right to know it was exercised.
 *
 * It does not include the resident's own actions on their own record, except the one this view
 * itself is: reading one's access log is an access, and is recorded as such, so the trail stays
 * complete.
 */

import { AuditAction, AuditEvent } from './audit-log';

/** The actions that disclose or read a resident's record, as distinct from changing it. */
export const DISCLOSURE_ACTIONS: readonly AuditAction[] = [
  'admin.read',
  'credential.verify',
  'oid4vp.presentation.verify',
  'oid4vci.credential.issue',
  'resident.access.read',
];

export type AccessActorKind = 'operator' | 'verifier' | 'relying_party' | 'wallet' | 'resident' | 'system';

export interface AccessLogEntry {
  /** The audit event's id, for a complaint to be investigated against the full trail. */
  eventId: string;
  at: string;
  action: AuditAction;
  /** Who, by kind. Never an operator's identity. */
  actorKind: AccessActorKind;
  /** For a relying party: its registered client identifier. Absent for every other kind. */
  relyingParty?: string;
  outcome: 'success' | 'failure';
}

/**
 * Classify an audit actor for a resident's eyes. Operator identities (`operator:<id>`,
 * `apikey:<id>`) collapse to `operator`; OAuth client identifiers surface as a relying party.
 */
export function classifyActor(action: AuditAction, actor: string): { kind: AccessActorKind; relyingParty?: string } {
  if (action === 'resident.access.read') return { kind: 'resident' };
  if (action === 'oid4vci.credential.issue') return { kind: 'wallet' };
  if (action === 'oid4vp.presentation.verify') return { kind: 'relying_party', relyingParty: actor === 'wallet' ? undefined : actor };
  if (action === 'credential.verify') return { kind: 'verifier' };
  if (/^(operator|apikey|admin):/i.test(actor) || actor === 'operator') return { kind: 'operator' };
  if (actor === 'system') return { kind: 'system' };
  return { kind: 'operator' };
}

/**
 * The access log for one resident: every disclosure event targeting their record, oldest
 * first, with actors reduced to kinds. Pure over the events it is given, so a store that pages
 * can feed it in pieces.
 */
export function accessLogFromEvents(events: Iterable<AuditEvent>, residentId: string): AccessLogEntry[] {
  // Order by the chain's own sequence, not by timestamp alone: two events recorded within the
  // same millisecond share a timestamp, and the sequence is what the hash chain commits to.
  const relevant = [...events]
    .filter((e) => e.target === residentId && DISCLOSURE_ACTIONS.includes(e.action))
    .sort((a, b) => a.seq - b.seq);
  const out: AccessLogEntry[] = [];
  for (const e of relevant) {
    const { kind, relyingParty } = classifyActor(e.action, e.actor);
    const entry: AccessLogEntry = { eventId: e.id, at: e.timestamp, action: e.action, actorKind: kind, outcome: e.outcome };
    if (relyingParty) entry.relyingParty = relyingParty;
    out.push(entry);
  }
  return out;
}

/** Read the access log through an audit reader that can filter by target. */
export async function accessLogFor(
  audit: { list(opts?: { limit?: number; offset?: number; target?: string }): Promise<AuditEvent[]> },
  residentId: string,
): Promise<AccessLogEntry[]> {
  const PAGE = 500;
  const all: AuditEvent[] = [];
  for (let offset = 0; ; offset += PAGE) {
    const page = await audit.list({ target: residentId, limit: PAGE, offset });
    all.push(...page);
    if (page.length < PAGE) break;
  }
  return accessLogFromEvents(all, residentId);
}
