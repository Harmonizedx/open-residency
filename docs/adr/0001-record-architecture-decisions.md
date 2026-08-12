# 1. Record architecture decisions

- Status: Proposed
- Date: 2026-07-30

## Context

We need to record the architectural decisions made on OpenResidency so the *reasoning*
survives contributor turnover — not just *what* the architecture is, but *why*, and which
alternatives were weighed. `docs/ARCHITECTURE.md` is a living description of the current
design; it does not capture decisions, their context, or the options considered.

## Decision

We will use **Architecture Decision Records (ADRs)**, as described by Michael Nygard, kept as
Markdown files under `docs/adr/`, numbered sequentially (`NNNN-title.md`). Substantive records
follow the **MADR** shape (context → options → decision → consequences).

An ADR is **immutable once Accepted**. To change a decision we add a *new* ADR that supersedes
the old one (and mark the old one `Superseded by ADR-NNNN`), rather than editing history.

Statuses: `Proposed` → `Accepted` → `Superseded` / `Deprecated`.

## Consequences

- Architectural reasoning lives beside the code, versioned and reviewed in the same PRs.
- New contributors can read the decision history instead of reverse-engineering intent.
- A small, ongoing discipline: each significant decision gets a short record.
- `docs/ARCHITECTURE.md` remains the living overview and links out to the relevant ADRs.
