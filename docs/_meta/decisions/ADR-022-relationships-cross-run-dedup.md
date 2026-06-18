# ADR-022 — Cross-run edge dedup: UNIQUE index on `relationships`

- **Status:** **proposed**
- **Date:** 2026-06-18
- **Authors:** AI/Agent Eng (team)
- **Stakeholders:** charter substrate maintainers; every agent `kg_writer` (writes edges via `add_relationship`); every PR reviewer.
- **Cycle:** v0.4 Stage 3 rest, PR1. Operator decision #718 Q-set (Q1–Q3). Builds on **ADR-018** (graph type catalogue) + **ADR-019** (shared `KnowledgeGraphWriterBase`).
- **Reference:** Stage 3 rest brainstorm `docs/superpowers/plans/2026-06-18-stage-3-rest-brainstorm.md`; debt memory `project_kg_loop_cross_run_dedup_debt`.

## Context

`SemanticStore.add_relationship` was **INSERT-only** and the `relationships` table carried **no
UNIQUE constraint** (only the non-unique lookup indexes `ix_relationships_src_type` /
`_dst_type` / `_tenant`). `KnowledgeGraphWriterBase` deduped edges **only within a single run**
via a per-instance `set[(src, dst, edge)]`. Across runs, every agent re-inserted the same edges,
so `AFFECTS` (and every other edge type) accumulated duplicates run over run — the known
KG-loop debt. `KnowledgeGraphWriterBase`'s own docstring already named a **DB UNIQUE constraint**
as the intended cross-run backstop; this ADR lands it. v0.4 Stage 3 (Option A — extend the
Postgres `SemanticStore`, no new datastore) is the authorized point to touch the substrate.

## Decision

Add a **cross-run dedup key** on `relationships` and make `add_relationship` idempotent against it.

1. **Key (Q2).** Uniqueness is `(tenant_id, src_entity_id, dst_entity_id, relationship_type)`.
   `properties` are **excluded** — exactly the within-run base key `(src, dst, edge)`, tenant-scoped.
   Two edges between the same endpoints with the same type collapse to one row even if their
   properties differ.

2. **Enforced as a UNIQUE _index_** (`uq_relationships_edge`), not a table constraint — so the
   migration is **portable to sqlite**, which cannot `ALTER TABLE ADD CONSTRAINT`. Declared both on
   the `RelationshipModel` (`Index(..., unique=True)`, so model-metadata `create_all` in unit tests
   carries it) and in alembic `0004_relationships_unique`.

3. **On-conflict semantics (Q1) — `DO NOTHING`, first-wins.** `add_relationship` uses the
   dialect-specific `insert(...).on_conflict_do_nothing(index_elements=[…])`
   (`postgresql` / `sqlite` dialects) with `RETURNING relationship_id`. On a conflict no row is
   returned → it `SELECT`s and returns the **first-written** `relationship_id`. Properties are
   **not** overwritten on a dedup hit. The audit `relationship_added` event is emitted **only on a
   real insert** (a dedup hit is not a graph mutation). The within-run `_seen_edges` set stays as a
   cheap pre-DB short-circuit, now backstopped by the DB.

4. **Back-dedup migration (Q3).** `0004` first deletes duplicate
   `(tenant_id, src, dst, relationship_type)` groups keeping `MIN(relationship_id)` (the
   first-written edge — matches first-wins), then creates the UNIQUE index. One-time, portable SQL
   (`DELETE … WHERE relationship_id NOT IN (SELECT MIN(...) GROUP BY …)`); lossless except for the
   discarded duplicates' properties.

## Consequences

- **Positive.** Cross-run duplicate edges are impossible at the DB layer; the graph's edge count is
  stable across re-runs (correct blast-radius / attack-path inputs for Stage 3 PR2 `kg_query`). The
  `add_relationship` signature and `int` return are unchanged — callers are unaffected.
- **Negative / accepted.** Properties drift (a later run with changed edge properties) is **not**
  reflected (first-wins, DO_NOTHING). If edge-property freshness ever matters, a `DO UPDATE` variant
  is a v0.5 follow-up. The back-dedup is a one-time data change on existing `relationships` rows.
- **Scope.** No new datastore (Postgres, Option A). Read surfaces (`kg_query`) and the
  findings-as-decorations migration are out of scope (PR2 / deferred).

## Alternatives considered

- **`DO UPDATE` (refresh properties).** Rejected for v0.4 (Q1) — first-wins matches the within-run
  base; property merge adds write amplification + ordering questions with no current consumer.
- **Application-level dedup only (keep the within-run set, add cross-run cache).** Rejected — a
  per-process cache cannot span runs/processes; the DB is the only correct cross-run boundary.
- **UNIQUE table constraint.** Rejected — not portable to sqlite without batch table-rebuild; a
  UNIQUE index is equivalent for both the constraint and the `ON CONFLICT` target.
