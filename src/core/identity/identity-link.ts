// SPDX-License-Identifier: Apache-2.0

/**
 * Identity links: which external identifiers belong to which person, and the record of
 * every time somebody decided that (ORCS §11).
 *
 * Until this existed, `subjectRef` -- the tokenized foundational identifier -- WAS the person.
 * The register had no way to say "this reference was attached to the wrong record", so an
 * identity-link error could only be fixed by editing rows in place or deleting one, and both
 * destroy the history that shows what happened and who did it. ADR-0012 removed the biggest
 * source of such errors (the same national number arriving through two routes) but not the
 * category: a clerk types a sibling's number, a duplicate is enrolled under a typo, a sector
 * system attaches its member number to the wrong resident.
 *
 * Six operations, taken from ORCS §11 verbatim:
 *
 * - LINK      associate an identifier with a person, after the checks the evidence names
 * - DISPUTE   mark a link as contested; high-risk use is restricted until it is resolved
 * - UNLINK    remove an association, preserving the history
 * - RELINK    move an identifier to the correct person, after adjudication
 * - MERGE     fold a duplicate person into the surviving one, under governed review
 * - SPLIT     reverse a merge and restore the separate persons
 *
 * ## Append-only
 *
 * Nothing here is ever deleted or overwritten in a way that loses what was true before. A
 * link that stops applying becomes UNLINKED and keeps its dates and reasons; a RELINK, MERGE
 * or SPLIT writes a NEW link and points the old one at it (`supersededBy`); every operation
 * appends an event naming who did it and why. The registry is the history, not a snapshot
 * of the current answer with the history thrown away.
 *
 * ## Which person
 *
 * ORCS §4.1 gives Person a stable internal identifier. In this deployment that is the
 * residency record's `residentId`: one deployment is one jurisdiction (ADR-0004), so a person
 * has at most one record here and its id is the stable handle everything else already uses.
 *
 * ## Which identifier
 *
 * Only a tokenized reference is ever stored -- the same HMAC that produces `subjectRef`,
 * namespaced by identifier type -- so this registry holds no national numbers, no sector
 * member numbers, and nothing that correlates across deployments. See `tokenizeSubject`.
 */

export type IdentityLinkStatus = 'ACTIVE' | 'DISPUTED' | 'UNLINKED';

/**
 * The ORCS §11 operations, plus the closing half of DISPUTE. A dispute that can only ever be
 * resolved by unlinking would presume the link was wrong; `DISPUTE_RESOLVED` records the
 * other outcome, that review found the link correct and use may resume.
 */
export type IdentityLinkOperation =
  | 'LINK'
  | 'DISPUTE'
  | 'DISPUTE_RESOLVED'
  | 'UNLINK'
  | 'RELINK'
  | 'MERGE'
  | 'SPLIT';

export interface IdentityLink {
  id: string;
  /** The person, as the residency record's `residentId`. */
  personRef: string;
  /** The identifier's namespace: `nin`, `aadhaar`, a provider code, or a sector scheme. */
  identifierType: string;
  /** Tokenized. Never the identifier itself. */
  identifierRef: string;
  status: IdentityLinkStatus;
  /**
   * True for the identifier the register verified this person against -- the one that is
   * their `subjectRef`. Unlinking it is what ORCS §7 means by "unlink and re-evaluate", so
   * the caller suspends the relationship first.
   */
  foundational: boolean;
  /** What the LINK decision rested on, by reference. Required: a link with no evidence is a guess. */
  evidenceRefs: string[];
  linkedAt: string;
  linkedBy: string;
  /** The open or most recent dispute. */
  dispute?: {
    raisedAt: string;
    raisedBy: string;
    reason: string;
    resolvedAt?: string;
    resolvedBy?: string;
    resolution?: string;
  };
  unlinked?: { at: string; by: string; reason: string; operation: 'UNLINK' | 'RELINK' | 'MERGE' | 'SPLIT' };
  /** For a link created by RELINK, MERGE or SPLIT: the link it continues. */
  supersedes?: string;
  /** For a link closed by RELINK, MERGE or SPLIT: the link that continues it. */
  supersededBy?: string;
  /** The merge that created this link on the survivor, so a SPLIT can find it. */
  mergeId?: string;
}

export interface IdentityLinkEvent {
  id: string;
  /** Monotonic within the store, so history reads in the order it happened. */
  seq: number;
  linkId: string;
  personRef: string;
  operation: IdentityLinkOperation;
  at: string;
  /** An operator identity. Never a bare "system": every one of these is somebody's decision. */
  by: string;
  reason?: string;
  evidenceRefs?: string[];
  /** For RELINK, MERGE and SPLIT: where the identifier moved from and to. */
  fromPersonRef?: string;
  toPersonRef?: string;
  mergeId?: string;
}

export interface MergeRecord {
  id: string;
  survivorRef: string;
  duplicateRef: string;
  at: string;
  by: string;
  reason: string;
  /** [duplicate's link id, survivor's new link id] per identifier moved. */
  moved: Array<{ from: string; to: string }>;
  split?: { at: string; by: string; reason: string; restored: Array<{ from: string; to: string }> };
}

/** Persistence port, mirroring the other stores in this tree. */
export interface IdentityLinkStore {
  saveLink(link: IdentityLink): Promise<IdentityLink>;
  findLink(id: string): Promise<IdentityLink | null>;
  /** The ACTIVE or DISPUTED link for an identifier, if any. At most one: an identifier belongs to one person. */
  findCurrentByIdentifier(identifierRef: string): Promise<IdentityLink | null>;
  listByPerson(personRef: string): Promise<IdentityLink[]>;
  appendEvent(event: Omit<IdentityLinkEvent, 'seq'>): Promise<IdentityLinkEvent>;
  listEvents(filter: { linkId?: string; personRef?: string }): Promise<IdentityLinkEvent[]>;
  saveMerge(merge: MergeRecord): Promise<MergeRecord>;
  findMerge(id: string): Promise<MergeRecord | null>;
}

/** In-memory implementation, for the smoke tests, the conformance suite and single-node pilots. */
export class InMemoryIdentityLinkStore implements IdentityLinkStore {
  private links = new Map<string, IdentityLink>();
  private events: IdentityLinkEvent[] = [];
  private merges = new Map<string, MergeRecord>();

  async saveLink(link: IdentityLink): Promise<IdentityLink> {
    this.links.set(link.id, { ...link });
    return link;
  }
  async findLink(id: string): Promise<IdentityLink | null> {
    return this.links.get(id) ?? null;
  }
  async findCurrentByIdentifier(identifierRef: string): Promise<IdentityLink | null> {
    return (
      [...this.links.values()].find(
        (l) => l.identifierRef === identifierRef && l.status !== 'UNLINKED',
      ) ?? null
    );
  }
  async listByPerson(personRef: string): Promise<IdentityLink[]> {
    return [...this.links.values()]
      .filter((l) => l.personRef === personRef)
      .sort((a, b) => (a.linkedAt < b.linkedAt ? -1 : 1));
  }
  async appendEvent(event: Omit<IdentityLinkEvent, 'seq'>): Promise<IdentityLinkEvent> {
    const full = { ...event, seq: this.events.length + 1 };
    this.events.push(full);
    return full;
  }
  async listEvents(filter: { linkId?: string; personRef?: string }): Promise<IdentityLinkEvent[]> {
    return this.events.filter(
      (e) =>
        (filter.linkId === undefined || e.linkId === filter.linkId) &&
        (filter.personRef === undefined ||
          e.personRef === filter.personRef ||
          e.fromPersonRef === filter.personRef ||
          e.toPersonRef === filter.personRef),
    );
  }
  async saveMerge(merge: MergeRecord): Promise<MergeRecord> {
    this.merges.set(merge.id, { ...merge });
    return merge;
  }
  async findMerge(id: string): Promise<MergeRecord | null> {
    return this.merges.get(id) ?? null;
  }
}

export type LinkOutcome<T> = ({ ok: true } & T) | { ok: false; reason: string };

export interface LinkRequest {
  personRef: string;
  identifierType: string;
  identifierRef: string;
  by: string;
  evidenceRefs: string[];
  foundational?: boolean;
  reason?: string;
  at?: string;
}

/**
 * The registry. Pure over its store: no framework, no clock of its own unless injected, so
 * the conformance suite can drive every operation without booting anything.
 */
export class IdentityLinkRegistry {
  constructor(
    private store: IdentityLinkStore,
    private now: () => string = () => new Date().toISOString(),
    private newId: () => string = () => crypto.randomUUID(),
  ) {}

  /**
   * LINK. Idempotent for the same person and identifier; refused when the identifier is
   * currently linked to somebody else, because two people cannot hold one identifier and
   * silently taking it from the first is exactly the error this registry exists to make
   * visible. Use DISPUTE, UNLINK or RELINK on the existing link instead.
   */
  async link(req: LinkRequest): Promise<LinkOutcome<{ link: IdentityLink; created: boolean }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.identifierType?.trim() || !req.identifierRef?.trim()) {
      return { ok: false, reason: 'IDENTIFIER_REQUIRED' };
    }
    if (!req.evidenceRefs?.some((e) => e.trim())) return { ok: false, reason: 'EVIDENCE_REQUIRED' };

    const current = await this.store.findCurrentByIdentifier(req.identifierRef);
    if (current) {
      if (current.personRef === req.personRef) return { ok: true, link: current, created: false };
      return { ok: false, reason: 'IDENTIFIER_LINKED_TO_ANOTHER_PERSON' };
    }

    const at = req.at ?? this.now();
    const link: IdentityLink = {
      id: this.newId(),
      personRef: req.personRef,
      identifierType: req.identifierType.trim().toLowerCase(),
      identifierRef: req.identifierRef,
      status: 'ACTIVE',
      foundational: !!req.foundational,
      evidenceRefs: req.evidenceRefs.map((e) => e.trim()).filter(Boolean),
      linkedAt: at,
      linkedBy: who,
    };
    await this.store.saveLink(link);
    await this.store.appendEvent({
      id: this.newId(),
      linkId: link.id,
      personRef: link.personRef,
      operation: 'LINK',
      at,
      by: who,
      reason: req.reason,
      evidenceRefs: link.evidenceRefs,
    });
    return { ok: true, link, created: true };
  }

  /** DISPUTE. The link stays in place, but `restrictions()` reports the person as restricted. */
  async dispute(
    linkId: string,
    req: { by: string; reason: string; at?: string },
  ): Promise<LinkOutcome<{ link: IdentityLink }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    const link = await this.store.findLink(linkId);
    if (!link) return { ok: false, reason: 'UNKNOWN_LINK' };
    if (link.status === 'UNLINKED') return { ok: false, reason: 'LINK_NOT_CURRENT' };
    if (link.status === 'DISPUTED') return { ok: false, reason: 'ALREADY_DISPUTED' };

    const at = req.at ?? this.now();
    const updated: IdentityLink = {
      ...link,
      status: 'DISPUTED',
      dispute: { raisedAt: at, raisedBy: who, reason: req.reason.trim() },
    };
    await this.store.saveLink(updated);
    await this.store.appendEvent({
      id: this.newId(),
      linkId,
      personRef: link.personRef,
      operation: 'DISPUTE',
      at,
      by: who,
      reason: req.reason.trim(),
    });
    return { ok: true, link: updated };
  }

  /**
   * Close a dispute in the link's favour: review found it correct. The other outcomes of a
   * review are UNLINK or RELINK, which close the dispute by closing the link.
   */
  async resolveDispute(
    linkId: string,
    req: { by: string; resolution: string; at?: string },
  ): Promise<LinkOutcome<{ link: IdentityLink }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.resolution?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    const link = await this.store.findLink(linkId);
    if (!link) return { ok: false, reason: 'UNKNOWN_LINK' };
    if (link.status !== 'DISPUTED' || !link.dispute) return { ok: false, reason: 'LINK_NOT_DISPUTED' };

    const at = req.at ?? this.now();
    const updated: IdentityLink = {
      ...link,
      status: 'ACTIVE',
      dispute: { ...link.dispute, resolvedAt: at, resolvedBy: who, resolution: req.resolution.trim() },
    };
    await this.store.saveLink(updated);
    await this.store.appendEvent({
      id: this.newId(),
      linkId,
      personRef: link.personRef,
      operation: 'DISPUTE_RESOLVED',
      at,
      by: who,
      reason: req.resolution.trim(),
    });
    return { ok: true, link: updated };
  }

  /** UNLINK. The link becomes UNLINKED and keeps everything it recorded. */
  async unlink(
    linkId: string,
    req: { by: string; reason: string; at?: string },
  ): Promise<LinkOutcome<{ link: IdentityLink }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    const link = await this.store.findLink(linkId);
    if (!link) return { ok: false, reason: 'UNKNOWN_LINK' };
    if (link.status === 'UNLINKED') return { ok: false, reason: 'ALREADY_UNLINKED' };

    const at = req.at ?? this.now();
    const updated = await this.close(link, { at, by: who, reason: req.reason.trim(), operation: 'UNLINK' });
    await this.store.appendEvent({
      id: this.newId(),
      linkId,
      personRef: link.personRef,
      operation: 'UNLINK',
      at,
      by: who,
      reason: req.reason.trim(),
    });
    return { ok: true, link: updated };
  }

  /**
   * RELINK. Closes the link on the person it was wrongly attached to and opens a new one on
   * the right person, each pointing at the other. Accepts an UNLINKED source too: an
   * identifier unlinked earlier can be relinked once adjudication says where it belongs.
   */
  async relink(
    linkId: string,
    req: { toPersonRef: string; by: string; reason: string; evidenceRefs: string[]; at?: string },
  ): Promise<LinkOutcome<{ from: IdentityLink; to: IdentityLink }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    if (!req.evidenceRefs?.some((e) => e.trim())) return { ok: false, reason: 'EVIDENCE_REQUIRED' };
    if (!req.toPersonRef?.trim()) return { ok: false, reason: 'TARGET_PERSON_REQUIRED' };
    const link = await this.store.findLink(linkId);
    if (!link) return { ok: false, reason: 'UNKNOWN_LINK' };
    const current = await this.store.findCurrentByIdentifier(link.identifierRef);
    if (current && current.id !== link.id) {
      // The identifier moved on since this link was closed; relink from where it is now.
      return { ok: false, reason: 'IDENTIFIER_LINKED_TO_ANOTHER_PERSON' };
    }
    if (link.personRef === req.toPersonRef) return { ok: false, reason: 'ALREADY_LINKED_TO_THAT_PERSON' };

    const at = req.at ?? this.now();
    const reason = req.reason.trim();
    const to: IdentityLink = {
      id: this.newId(),
      personRef: req.toPersonRef,
      identifierType: link.identifierType,
      identifierRef: link.identifierRef,
      status: 'ACTIVE',
      foundational: link.foundational,
      evidenceRefs: req.evidenceRefs.map((e) => e.trim()).filter(Boolean),
      linkedAt: at,
      linkedBy: who,
      supersedes: link.id,
    };
    const from =
      link.status === 'UNLINKED'
        ? await this.store.saveLink({ ...link, supersededBy: to.id })
        : await this.close(link, { at, by: who, reason, operation: 'RELINK' }, to.id);
    await this.store.saveLink(to);
    await this.store.appendEvent({
      id: this.newId(),
      linkId: to.id,
      personRef: to.personRef,
      operation: 'RELINK',
      at,
      by: who,
      reason,
      evidenceRefs: to.evidenceRefs,
      fromPersonRef: link.personRef,
      toPersonRef: to.personRef,
    });
    return { ok: true, from, to };
  }

  /**
   * MERGE. Every current link of the duplicate moves to the survivor. Refused while any of
   * them is DISPUTED: a merge is meant to be the outcome of review, not a way around one.
   * What happens to the duplicate's residency relationship is the caller's decision -- see
   * ResidencyService.mergeResidents, which ends it with a reason naming the survivor.
   */
  async merge(req: {
    survivorRef: string;
    duplicateRef: string;
    by: string;
    reason: string;
    at?: string;
  }): Promise<LinkOutcome<{ merge: MergeRecord }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    if (req.survivorRef === req.duplicateRef) return { ok: false, reason: 'CANNOT_MERGE_PERSON_WITH_SELF' };

    const links = (await this.store.listByPerson(req.duplicateRef)).filter((l) => l.status !== 'UNLINKED');
    if (links.length === 0) return { ok: false, reason: 'NOTHING_TO_MERGE' };
    if (links.some((l) => l.status === 'DISPUTED')) return { ok: false, reason: 'DISPUTED_LINKS_MUST_BE_RESOLVED' };

    const at = req.at ?? this.now();
    const reason = req.reason.trim();
    const merge: MergeRecord = {
      id: this.newId(),
      survivorRef: req.survivorRef,
      duplicateRef: req.duplicateRef,
      at,
      by: who,
      reason,
      moved: [],
    };
    for (const link of links) {
      const to: IdentityLink = {
        id: this.newId(),
        personRef: req.survivorRef,
        identifierType: link.identifierType,
        identifierRef: link.identifierRef,
        status: 'ACTIVE',
        foundational: link.foundational,
        evidenceRefs: [`merge:${merge.id}`, ...link.evidenceRefs],
        linkedAt: at,
        linkedBy: who,
        supersedes: link.id,
        mergeId: merge.id,
      };
      await this.close(link, { at, by: who, reason, operation: 'MERGE' }, to.id);
      await this.store.saveLink(to);
      await this.store.appendEvent({
        id: this.newId(),
        linkId: to.id,
        personRef: req.survivorRef,
        operation: 'MERGE',
        at,
        by: who,
        reason,
        fromPersonRef: req.duplicateRef,
        toPersonRef: req.survivorRef,
        mergeId: merge.id,
      });
      merge.moved.push({ from: link.id, to: to.id });
    }
    await this.store.saveMerge(merge);
    return { ok: true, merge };
  }

  /**
   * SPLIT. Reverses a merge: each link the merge created on the survivor is closed and the
   * identifier is restored to the duplicate on a new link. Refused if any of those links has
   * since been moved again, because reversing over the top of a later decision would undo
   * it without anyone having chosen to.
   */
  async split(
    mergeId: string,
    req: { by: string; reason: string; at?: string },
  ): Promise<LinkOutcome<{ merge: MergeRecord }>> {
    const who = actor(req.by);
    if (!who) return { ok: false, reason: 'DECIDING_ACTOR_REQUIRED' };
    if (!req.reason?.trim()) return { ok: false, reason: 'REASON_REQUIRED' };
    const merge = await this.store.findMerge(mergeId);
    if (!merge) return { ok: false, reason: 'UNKNOWN_MERGE' };
    if (merge.split) return { ok: false, reason: 'ALREADY_SPLIT' };

    const survivorLinks: IdentityLink[] = [];
    for (const { to } of merge.moved) {
      const l = await this.store.findLink(to);
      if (!l || l.status === 'UNLINKED') return { ok: false, reason: 'LINK_MOVED_SINCE_MERGE' };
      survivorLinks.push(l);
    }

    const at = req.at ?? this.now();
    const reason = req.reason.trim();
    const restored: Array<{ from: string; to: string }> = [];
    for (const link of survivorLinks) {
      const original = await this.store.findLink(link.supersedes!);
      const back: IdentityLink = {
        id: this.newId(),
        personRef: merge.duplicateRef,
        identifierType: link.identifierType,
        identifierRef: link.identifierRef,
        status: 'ACTIVE',
        foundational: link.foundational,
        evidenceRefs: [`split:${merge.id}`, ...(original?.evidenceRefs ?? [])],
        linkedAt: at,
        linkedBy: who,
        supersedes: link.id,
      };
      await this.close(link, { at, by: who, reason, operation: 'SPLIT' }, back.id);
      await this.store.saveLink(back);
      await this.store.appendEvent({
        id: this.newId(),
        linkId: back.id,
        personRef: merge.duplicateRef,
        operation: 'SPLIT',
        at,
        by: who,
        reason,
        fromPersonRef: merge.survivorRef,
        toPersonRef: merge.duplicateRef,
        mergeId: merge.id,
      });
      restored.push({ from: link.id, to: back.id });
    }
    const updated: MergeRecord = { ...merge, split: { at, by: who, reason, restored } };
    await this.store.saveMerge(updated);
    return { ok: true, merge: updated };
  }

  /** Which person an identifier currently belongs to, or null. Disputed links still resolve. */
  async resolvePerson(identifierRef: string): Promise<string | null> {
    const current = await this.store.findCurrentByIdentifier(identifierRef);
    return current?.personRef ?? null;
  }

  /**
   * Whether high-risk use is restricted for a person (ORCS §11 DISPUTE). Issuing or
   * re-issuing a credential is high-risk use; reading the record is not.
   */
  async restrictions(personRef: string): Promise<{ restricted: boolean; disputedLinkIds: string[] }> {
    const disputed = (await this.store.listByPerson(personRef)).filter((l) => l.status === 'DISPUTED');
    return { restricted: disputed.length > 0, disputedLinkIds: disputed.map((l) => l.id) };
  }

  async linksFor(personRef: string): Promise<IdentityLink[]> {
    return this.store.listByPerson(personRef);
  }
  async find(linkId: string): Promise<IdentityLink | null> {
    return this.store.findLink(linkId);
  }
  /**
   * Everything that happened to one link. A RELINK, MERGE or SPLIT is one operation and one
   * event, recorded on the link it created; the link it closed shows that closing here too,
   * so reading either side gives the whole story.
   */
  async history(linkId: string): Promise<IdentityLinkEvent[]> {
    const own = await this.store.listEvents({ linkId });
    const link = await this.store.findLink(linkId);
    if (!link?.supersededBy) return own;
    const closing = (await this.store.listEvents({ linkId: link.supersededBy })).filter((e) =>
      ['RELINK', 'MERGE', 'SPLIT'].includes(e.operation),
    );
    return [...own, ...closing].sort((a, b) => a.seq - b.seq);
  }
  async historyFor(personRef: string): Promise<IdentityLinkEvent[]> {
    return this.store.listEvents({ personRef });
  }
  async merged(mergeId: string): Promise<MergeRecord | null> {
    return this.store.findMerge(mergeId);
  }

  private async close(
    link: IdentityLink,
    closing: { at: string; by: string; reason: string; operation: 'UNLINK' | 'RELINK' | 'MERGE' | 'SPLIT' },
    supersededBy?: string,
  ): Promise<IdentityLink> {
    const updated: IdentityLink = {
      ...link,
      status: 'UNLINKED',
      unlinked: closing,
      supersededBy: supersededBy ?? link.supersededBy,
      // A dispute open at the moment of closing is closed by the closing itself.
      dispute:
        link.dispute && !link.dispute.resolvedAt
          ? { ...link.dispute, resolvedAt: closing.at, resolvedBy: closing.by, resolution: `${closing.operation}: ${closing.reason}` }
          : link.dispute,
    };
    return this.store.saveLink(updated);
  }
}

function actor(by: string | undefined): string | null {
  const v = by?.trim();
  return v ? v : null;
}
