# Stage 3 rest — v0.4 brainstorm (cross-run dedup fix + kg_query 3-hop)

_2026-06-18 · v0.4 Stage 3 (fleet-graph wiring, Option A — extend Postgres SemanticStore) · per #718 locked decisions_

## 1. Where Stage 3 stands (recon, 2026-06-18)

Stages 1+2 folded inventory discovery into each agent (Option X) and put the inventory-writing
agents on the graph via per-agent `kg_writer`s on `KnowledgeGraphWriterBase` (ADR-019), all
catalogue-typed against ADR-018 `graph_types` (`NodeCategory` / `EdgeType`). The fleet now writes
typed nodes + edges into the Postgres `SemanticStore` (`entities` + `relationships`). Two pieces
of Stage 3 §5 remain (the "rest"):

- **Edge writes are not cross-run idempotent.** `SemanticStore.add_relationship` is INSERT-only;
  `relationships` carries **no UNIQUE constraint** (only non-unique indexes
  `ix_relationships_src_type` / `_dst_type` / `_tenant`). `KnowledgeGraphWriterBase` dedups
  **within a run** via a per-instance `_seen_edges: set[(src, dst, edge)]`, but every new run
  re-inserts the same edges → duplicate `AFFECTS` (and every other) edge accumulation across runs
  (the known debt — `project_kg_loop_cross_run_dedup_debt`). The base's own docstring already
  names a **DB UNIQUE constraint** as the intended cross-run backstop. This is a **charter
  substrate** change.
- **No read surface for 3-hop correlation.** `SemanticStore` exposes `neighbors` (outgoing BFS to
  `MAX_TRAVERSAL_DEPTH = 3`, returns reachable _entities_ — not paths), `get_entity`,
  `list_entities_by_type`. There is **no `kg_query`** module: nothing turns the graph into
  blast-radius / attack-path answers (directive §5-D, P-6 3-hop). A.4 (meta-harness) is the
  cross-agent reasoner and the natural first consumer.

The `graph_types` catalogue already reserves the result-side node categories `ATTACK_PATH`,
`BLAST_RADIUS_RECORD`, `TOXIC_COMBINATION` — but **writing** those as decorations is the deferred
findings-as-decorations migration, out of scope for this "rest".

## 2. The two items vs current state

| Item                   | Current                                                                        | Target                                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **A. cross-run dedup** | `relationships` no UNIQUE; `add_relationship` INSERT-only; within-run set only | UNIQUE `(tenant_id, src, dst, relationship_type)`; `add_relationship` idempotent; cross-run dup-free      |
| **B. kg_query 3-hop**  | only `neighbors` (entities, not paths); no query module                        | A.4-only `kg_query`: catalogue-typed blast-radius (downstream 3-hop) + attack-path (the chain), read-only |

## 3. Proposed sequencing (2 PRs, sequence via main — no stacking)

**PR1 — cross-run dedup UNIQUE constraint (substrate; ADR-022 + per-PR review).**

- Alembic `0004_relationships_unique.py`: (1) **back-dedup** existing rows — delete duplicate
  `(tenant_id, src_entity_id, dst_entity_id, relationship_type)` groups keeping `MIN(relationship_id)`;
  (2) add `UniqueConstraint("tenant_id", "src_entity_id", "dst_entity_id", "relationship_type",
name="uq_relationships_edge")`. Portable (Postgres + sqlite); real-Postgres CI proof (the F.5
  alembic-against-real-Postgres lane).
- `add_relationship` → **idempotent**: `ON CONFLICT DO NOTHING` (Postgres) / `INSERT OR IGNORE`
  (sqlite); on conflict, `SELECT` and return the existing `relationship_id` (preserve the `int`
  return contract). Within-run `_seen_edges` stays as a cheap pre-DB short-circuit, now backstopped.
- ADR-022 documents the UNIQUE key, on-conflict semantics, and the back-dedup migration step.

**PR2 — kg_query 3-hop A.4-only (consumer; self-merge cascade).**

- `meta_harness/kg_query.py`: read-only, catalogue-typed (`EdgeType` / `NodeCategory`), depth
  clamped to `MAX_TRAVERSAL_DEPTH`.
  - `blast_radius(entity_id, edge_types, depth≤3)` — downstream impact via outgoing BFS (builds on
    `neighbors`); returns typed reachable nodes.
  - `attack_path(src, dst, max_depth≤3)` — the actual chain(s) between two nodes.
- Attack-path needs a **path-aware read** (`neighbors` discards paths). Smallest honest addition:
  one **read-only** primitive on `SemanticStore` (`outgoing_edges` or `traverse_paths`) — additive
  API, **no schema change, not a seal event** (see Q4). kg_query reconstructs paths over it.
- Returns typed DTOs only — **does not write** `ATTACK_PATH` / `BLAST_RADIUS_RECORD` nodes (that
  decorations migration stays deferred, Q5).

## 4. Swiss bar

Real backends (alembic against real Postgres + sqlite; the dedup migration runs on a seeded
duplicate-edge fixture and is verified idempotent). Real read tests against a populated graph.
Substrate touch = PR1 only → ADR-022 + per-PR review; the read-primitive question (Q4) decides
whether PR2 touches charter at all. No new datastore (Postgres, Option A). No findings-as-
decorations (deferred). `add_relationship` stays byte-compatible for callers (same signature,
same `int` return). No reverse-parsing of OCSF dicts.

## 5. Open questions for the operator (Q-set)

- **Q1 — on-conflict semantics.** On a duplicate edge: `DO NOTHING` (first-wins; matches the
  within-run base which skips repeats) vs `DO UPDATE` (refresh `properties` to the latest write)?
  _Rec: **DO NOTHING** — first-wins, matches the `(src,dst,edge)` base dedup; properties drift is a
  v0.5 concern if it ever matters._
- **Q2 — UNIQUE key.** `(tenant_id, src_entity_id, dst_entity_id, relationship_type)` — properties
  **excluded** (so two edges differing only by properties collapse to one). Confirm. _Rec: yes —
  exactly the within-run base key, tenant-scoped._
- **Q3 — back-dedup of existing rows.** The migration deletes duplicate groups keeping
  `MIN(relationship_id)` before adding the constraint. This is a one-time, lossless-except-dup-
  properties data change on `relationships`. Confirm OK. _Rec: yes — the duplicates are the bug._
- **Q4 — kg_query path primitive placement.** Attack-path needs a read-only edge/path primitive on
  `SemanticStore`. Treat it as **(a)** part of PR1 (substrate, per-PR review) or **(b)** part of PR2
  (self-merge) since it is read-only and changes no schema? _Rec: **(b)** — read-only API additions
  are not seal events; bundle with kg_query, self-merge._
- **Q5 — kg_query output.** Read-only typed DTOs (paths / blast-radius records returned, **not**
  written as graph nodes). Confirm the findings-as-decorations migration stays **deferred** (not in
  this rest). _Rec: yes — read-only this cycle._
- **Q6 — A.4-only scope.** `kg_query` lives in meta-harness and is consumed only by A.4 this cycle;
  other agents wire in as consumers in v0.5. Confirm. _Rec: yes — A.4-only, per your scope._
- **Q7 — review mode.** Per-PR review on PR1 (ADR-022 + migration + `add_relationship`); self-merge
  cascade on PR2 (kg*query). \_Rec: as locked in your message.*

## 6. Non-goals (this rest)

- Findings-as-decorations migration (OCSF anchors as graph nodes) — deferred.
- Neo4j / any new datastore (ADR-009 swap stays the dormant escape hatch).
- Deep cascade depth ≥ 5 — `MAX_TRAVERSAL_DEPTH` stays 3 (P-6); deeper → v0.5+.
- Multi-agent kg_query consumers — A.4-only now.
- Recursive-CTE traversal optimization — the iterative BFS stays until the graph outgrows it.
