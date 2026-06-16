# ADR-018 — Graph type catalogue in charter (fleet-graph entity/edge types)

- **Status:** **proposed**
- **Date:** 2026-06-16
- **Authors:** AI/Agent Eng (team)
- **Stakeholders:** every agent that writes inventory (`kg_writer`); A.4 Meta-Harness (`kg_query` consumer); charter substrate maintainers; every PR reviewer.
- **Cycle:** v0.4 Stage 3 (fleet-graph extension), PR1. Directive `v0-4-directive-2026-06-16.md` §5 (Option A) + §9 (ADRs start 018). Operator decision #718-D2 (type module in **charter**).
- **Reference:** inventory catalogue `docs/_meta/v0-4-inventory-catalogue-2026-06-16.md` (#711); Stage 3 design brainstorm `docs/superpowers/plans/2026-06-16-stage-3-fleet-graph-design-brainstorm.md`.

## Context

v0.4 extends the **Postgres `SemanticStore`** (Option A; no Neo4j — ADR-009 escape hatch stays dormant) into a fleet inventory graph: findings become decorations on a connected entity graph (the inventory catalogue's core insight). Six agents already write to the store; v0.4 Stage 1/2 add ~6 more, and Stage 3 adds a `kg_query` read surface (3-hop blast-radius / attack-path, consumed by A.4).

Today `SemanticStore.upsert_entity(entity_type=…)` and `add_relationship(relationship_type=…)` take **free strings** (`semantic.py`). Each of the 6 existing `kg_writer`s hardcodes its own type strings (copy-pattern). With ~12 writers + a query layer all referencing the same node/edge typology, free strings are a correctness hazard: a typo in one agent's `"VULNERABLE_TO"` vs the query's expectation silently breaks traversal, and nothing enforces the catalogue's ownership rules.

The inventory catalogue (#711) is the authoritative node/edge typology. It needs a **single codified source of truth** the writers and the query layer both import.

## Decision

**Codify the inventory catalogue's node categories and edge types as a charter type-catalogue module** — `charter/memory/graph_types.py` — exporting `NodeCategory` and `EdgeType` string enums, transcribed faithfully from #711 (Layer 23 transcription discipline; no fabricated types).

- **Placement: charter** (operator decision #718-D2). charter is the institutional substrate the `kg_writer`s already import (`SemanticStore`); the type catalogue is foundational and belongs beside the store it types. Not `nexus_runtime` (deps=[] canary) and not `shared` (the types are charter-memory-scoped).
- **String enums** (`StrEnum`) so existing `entity_type=…` / `relationship_type=…` call sites accept them unchanged (a `NodeCategory`/`EdgeType` _is_ a `str`) — backward-compatible, no `SemanticStore` signature change.
- **Additive + non-breaking:** the store keeps accepting free strings (existing 6 writers unchanged until they opt in); new writers (Stage 1/2) use the enum. No migration forced; the enum is the forward standard.
- **Scope of this ADR/PR:** the type catalogue only. The **shared `KnowledgeGraphWriter` base** (#718-D1) is **ADR-019** (separate PR); `kg_query` (#718-D4, A.4-only) and the cross-run-dedup `UNIQUE(tenant, src, dst, type)` fix (#718-D3) are later Stage 3 PRs. This PR does not change `SemanticStore` behaviour.

## Sequencing (base-first)

This is PR1 of the fleet-graph foundation. The recommended order: **ADR-018 (this, type catalogue) → ADR-019 (shared writer base) → the Stage 1/2 per-agent `kg_writer`s consume both** → `kg_query` + dedup fix. Building the foundation first avoids refactoring ~12 per-agent writers later. Non-`kg_writer` Stage 1 depth (FIM, Falco/Tracee/osquery, CIS v2.0, inline-policy fetch, SAST languages) proceeds in parallel with no dependency on this ADR.

## Substrate + review

charter-touching → **per-PR review** (Trigger #48); substrate seal for _agent_ packages stays EMPTY (this is an authorized charter change, not an agent-cycle edit). Tenant isolation (ADR-007), 3-hop cap (P-6), and the dormant Neo4j door (ADR-009) are unaffected.

## Consequences

- **+** one source of truth for the graph typology; typo-class breakage becomes an import error / enum miss, not a silent traversal gap.
- **+** the query layer (A.4) and the writers share the exact edge vocabulary.
- **−** the catalogue typology must be kept in sync with #711 (the v1.1 catalogue amendment + future agents); the enum is the enforcement point, and a test asserts every catalogue edge has an `EdgeType` member.
- **Neutral:** existing free-string writers keep working; opt-in migration.

## Alternatives considered

- **Free strings (status quo)** — rejected: no enforcement; typo-fragile across 12 writers + a query layer.
- **Type module in `nexus_runtime`** — rejected: would either break the deps=[] canary (if it imported charter) or duplicate; the types are charter-memory-scoped.
- **Per-agent local enums** — rejected: re-introduces the divergence problem the catalogue exists to solve.
