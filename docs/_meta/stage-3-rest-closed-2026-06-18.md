# Stage 3 rest — v0.4 close record

_2026-06-18 · fleet-graph wiring (Option A — extend Postgres SemanticStore) · per #718_

## Scope delivered (2 PRs, sequenced via main)

| PR       | What                                                                                                                             | Review                    |
| -------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| **#759** | cross-run edge dedup (`uq_relationships_edge` + `ON CONFLICT DO NOTHING`) **+** `get_relationships_from` edge accessor · ADR-022 | substrate → per-PR review |
| **#760** | `meta_harness/kg_query.py` — 3-hop blast-radius + attack-path (A.4-only)                                                         | consumer → self-merge     |

(Brainstorm #758.)

## #759 — substrate (ADR-022)

The cross-run AFFECTS-edge duplication debt (`project_kg_loop_cross_run_dedup_debt`) is **closed**.
`relationships` now carries `uq_relationships_edge` on `(tenant_id, src_entity_id, dst_entity_id,
relationship_type)` — a UNIQUE _index_ (sqlite-portable; no `ALTER TABLE ADD CONSTRAINT`).
`add_relationship` is idempotent (dialect-aware `on_conflict_do_nothing`, first-wins, returns the
existing id, audits only on a real insert). Alembic `0004` back-dedups existing rows
(`MIN(relationship_id)`) before adding the index. Signature + `int` return unchanged → callers
unaffected. The Q4 edge accessor `get_relationships_from(*, tenant_id, src_entity_id,
edge_types=None) -> list[RelationshipRow]` (single-hop, read-only, tenant-scoped) folded into the
same PR per the operator's conditional.

**Q-set:** Q1 DO_NOTHING first-wins · Q2 key excludes properties · Q3 back-dedup keep MIN(id) ·
Q4 accessor rides per-PR-review substrate (folded into #759) · Q5 read-only · Q6 A.4-only · Q7
per-PR #759 / self-merge #760.

## #760 — consumer (A.4-only)

`KgQuery(semantic_store, customer_id)` — read-only correlation surface:

- `blast_radius` — downstream reachable entities; pure consumer of `neighbors` (no new charter dep).
- `attack_path` — all simple edge chains, via a **depth-bounded BFS reconstruction in the consumer**
  over `get_relationships_from` (path logic stays in meta-harness, not charter). Cycles excluded.
- Read-only DTOs `BlastRadiusResult` / `AttackPathResult` / `PathEdge`. Depth cap
  `MAX_TRAVERSAL_DEPTH` (3, P-6) preserved; tenant-scoped.
- **Decorations migration deferred** — no `ATTACK_PATH` / `BLAST_RADIUS_RECORD` node writes.

## Verification

- #759: 366 charter pass / 11 skip (gated real-Postgres incl. the `pg_insert` on-conflict + edge
  accessor tests); alembic stepwise back-dedup + unique-index materialization.
- #760: 716 meta-harness pass / 2 skip; real e2e vs in-memory `SemanticStore` (cloud→code sample
  graph) — blast radius, attack-path chain, all-simple-paths, depth cap, cycle exclusion, edge
  filter, tenant isolation.
- ruff + mypy clean both PRs; each PR's CI `python-tests` (full repo) green.

## Stage 3 status

Stage 3 (fleet-graph wiring) is **done**: agents write the typed graph (Stages 1+2), edges are
cross-run idempotent, and A.4 has a 3-hop read surface. **No new datastore** (Postgres, Option A).

## Carried to v0.5

- Findings-as-decorations migration (anchor OCSF findings as `ATTACK_PATH` / `BLAST_RADIUS_RECORD`
  graph nodes).
- kg_query consumers beyond A.4.
- `DO UPDATE` edge-property freshness (if ever needed); recursive-CTE traversal; depth ≥ 5 cascade.

## Next

Stage 4 (Wazuh 12-item) waits on the operator Wazuh spec; Stage 5 = v0.4 close + v0.5 readiness audit.
