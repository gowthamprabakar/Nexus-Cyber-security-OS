# ADR-019 — Shared `KnowledgeGraphWriter` base in charter

- **Status:** **proposed**
- **Date:** 2026-06-16
- **Authors:** AI/Agent Eng (team)
- **Stakeholders:** every agent that writes inventory (`kg_writer`); charter substrate maintainers; every PR reviewer.
- **Cycle:** v0.4 Stage 3 (fleet-graph extension), PR2. Operator decision #718-D1 (extract a thin shared base). Builds on **ADR-018** (graph type catalogue).
- **Reference:** Stage 3 design brainstorm `docs/superpowers/plans/2026-06-16-stage-3-fleet-graph-design-brainstorm.md`; inventory catalogue #711.

## Context

Six v0.2/v0.3 agents (cloud-posture, compliance, threat-intel, synthesis, curiosity, meta-harness) each **copy-pasted** the same `kg_writer` shape: constructor `(SemanticStore, customer_id)`, tenant-scoped writes, side-effect-only methods, and — where they write edges — a per-instance within-run dedup `set` (because `SemanticStore.add_relationship` is INSERT-only). v0.4 Stage 1/2 add **~6 more** writers (D.3-runtime, D.4-data, D.6-k8s, D.4-network, D.2-identity, D.14-appsec). Twelve writers re-implementing the same tenant-scoping + dedup + (now) typed-vocabulary boilerplate is a maintenance + correctness hazard — the within-run dedup, in particular, was re-derived per agent and is easy to omit.

The copy-pattern was _deliberately_ preserved through v0.2/v0.3 (ADR-009/010 substrate-sealing watch-items: don't hoist into charter mid-agent-cycle). v0.4 Stage 3 is the authorized point to consolidate (operator #718-D1).

## Decision

**Extract a thin `KnowledgeGraphWriterBase` into charter** — `charter/memory/kg_writer_base.py` — that each agent's `kg_writer` subclasses. The base owns the cross-cutting concerns; agents add only their domain methods.

The base provides:

- **Tenant scoping by construction** — pinned to `customer_id`; no per-call tenant → cross-tenant writes impossible (ADR-007).
- **Typed vocabulary** — `upsert_node(category: NodeCategory, …)` + `add_edge(src, dst, edge: EdgeType, …)` use the ADR-018 catalogue, not free strings.
- **Within-run edge dedup** — the per-instance `set` every edge-writing agent was re-implementing, now once.
- **Opt-in / inert** — `SemanticStore | None`; when `None`, methods short-circuit (single-tenant opt-in default, Path-B rule). `.enabled` exposes the state.

- **Scope (this PR):** the base only. It **composes** the existing `SemanticStore` API and changes **no** store behaviour. **Cross-run dedup** (a DB `UNIQUE(tenant, src, dst, type)` constraint + alembic migration, #718-D3) is a **separate Stage 3 PR** — not bundled here (migrations carry their own risk + review surface).
- **Migration of the 6 existing writers** to the base is **opt-in / follow-up**, not forced in this PR (keeps the blast radius small; they work as-is). New Stage 1/2 writers use the base from day one.

## Sequencing (base-first)

ADR-018 (types) → **ADR-019 (this, base)** → the Stage 1/2 per-agent `kg_writer`s subclass the base + consume the types (no rework) → `kg_query` (#718-D4) + cross-run dedup (#718-D3). Non-`kg_writer` Stage 1 depth runs in parallel with no dependency on either ADR.

## Substrate + review

charter-touching → **per-PR review** (Trigger #48); agent-package seal stays EMPTY. Composes existing `SemanticStore` (no signature/behaviour change). 3-hop cap (P-6), tenant isolation (ADR-007), dormant Neo4j (ADR-009) unaffected.

## Consequences

- **+** within-run dedup + tenant scoping + typed vocabulary implemented once; new writers can't omit them.
- **+** a uniform writer surface the `kg_query` layer (A.4) + reviewers can reason about.
- **−** two writer styles co-exist until the 6 legacy writers opt in (acceptable; tracked).
- **Neutral:** cross-run dedup still outstanding (its own PR, #718-D3) — the base is forward-compatible with it (no behaviour change needed when the DB constraint lands).

## Alternatives considered

- **Keep copy-pattern (status quo)** — rejected at 12 writers: dedup omission risk + free-string drift.
- **Bundle cross-run dedup here** — rejected: the `UNIQUE` constraint + alembic migration is a distinct risk/review surface; ship the base first, the constraint separately (#718-D3).
- **Mandatory migration of all 6 now** — rejected: unnecessary blast radius; opt-in keeps this PR thin.
