# v0.4 Stage 3 — Fleet-graph extension (Postgres SemanticStore) — design brainstorm

**Status:** design brainstorm for operator review (per-PR review). Runs PARALLEL with Stage 1 (Layer 35).
**Directive:** `v0-4-directive-2026-06-16.md` §5 (Option A locked). **Catalogue:** #711 (the inventory map).
**Scope:** DESIGN ONLY — no execution PRs (Stage 3 _execution_ needs Stages 1+2 mature). **Discipline:** extend Postgres SemanticStore; per-agent ownership; seal EMPTY; 3-hop.

> Terminology (Layer 32): "fleet-graph extension of the Postgres `SemanticStore`" — NOT an "inventory graph" stand-up, NOT Neo4j.

## 1. Current state (recon vs main `fec57f8`)

| Capability                               | State                                                                                                                                                                                     | Evidence                             |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| SemanticStore API                        | `upsert_entity` / `get_entity` / `add_relationship` (INSERT-ONLY) / `neighbors` (BFS) / `list_entities_by_type`                                                                           | `charter/memory/semantic.py`         |
| Traversal depth                          | **`MAX_TRAVERSAL_DEPTH = 3`** (hard cap, app-layer)                                                                                                                                       | `semantic.py:38,208`                 |
| kg_writers                               | **6 agents, copy-pattern, NO shared base** (cloud-posture/compliance/threat-intel/synthesis/curiosity/meta-harness); `(SemanticStore, customer_id)`, cross-tenant guard, side-effect-only | per-agent `kg_writer.py`             |
| kg_query                                 | **none** — only `neighbors()` via investigation's `memory_walk.py`                                                                                                                        | `investigation/tools/memory_walk.py` |
| attack-path / blast-radius graph queries | **none** (A.1 "blast radius" = mutation-count safety gate, not a graph query)                                                                                                             | `remediation/authz.py`               |
| Neo4j                                    | **dormant** (cloud-posture `neo4j_kg.py`, not in run())                                                                                                                                   | confirmed                            |
| cross-run relationship dedup             | **known debt** (`add_relationship` insert-only)                                                                                                                                           | threat-intel kg_writer note          |

## 2. Goal + scope boundary

- **Goal:** codify the inventory catalogue (#711) into the SemanticStore schema; bring the remaining agents' inventory writes online (Stage 1/2 add their kg_writers); add a `kg_query` read surface (3-hop blast-radius / attack-path); migrate findings to anchor on graph nodes.
- **Covers:** schema codification (entity/relationship types from the catalogue); kg_writer pattern consistency; `kg_query`; findings-as-decorations; cross-run dedup fix.
- **Does NOT cover:** Neo4j (Option A locked; ADR-009 escape hatch for depth≥5 → v0.5); deep cascade correlation depth≥5 (v0.5); the per-agent discovery sweeps (those land in Stage 1/2 per Option X).

## 3. Approach — per layer (options + rec)

- **3a Catalogue → schema.** Codify the catalogue's node categories + edge typology as SemanticStore entity_type / relationship_type constants + a validation surface. Rec: a shared `nexus_runtime`-level (or charter) catalogue-of-types module the kg_writers import — **OPEN: shared types module placement** (charter vs nexus_runtime vs shared) — touches substrate → ADR + per-PR review (Trigger #48).
- **3b kg_writer interface — shared base vs copy-pattern.** Today: 6 copy-pattern writers (deliberate, per ADR-009/010 sealing). Stage 1/2 add ~6 more (D.3-runtime, D.4-data, D.6-k8s, D.4-network, D.2-identity, D.14-appsec). **OPEN DECISION:** (i) keep copy-pattern (consistent, sealed, but 12× duplication); (ii) extract a shared `KnowledgeGraphWriter` base/protocol into charter/nexus_runtime (DRY, but substrate touch + ADR + Trigger #48). Rec: **(ii) extract a thin shared base now** — 12 writers justifies it; do it as an operator-reviewed substrate PR with an ADR. Surface for decision.
- **3c kg_query (3-hop).** New read surface: blast-radius (`neighbors` depth≤3 from a seed finding/resource) + attack-path (typed-edge traversal) + toxic-combination patterns. Built on the existing `neighbors()` (depth≤3, P-6). Per-PR review (shared interface). Consumer = A.4 Meta-Harness (catalogue).
- **3d findings-as-decorations migration.** Existing OCSF emissions gain `affected_entity_id` linking to graph nodes; backward-compatible (additive). Per-agent.
- **3e cross-run relationship dedup.** Fix the known `add_relationship` insert-only debt (dedup on `(tenant, src, dst, type)`), so multi-run inventory doesn't accumulate duplicate edges. Substrate-adjacent (charter) → per-PR review + ADR.

## 4. Sub-PR breakdown (DESIGN now; execution after Stages 1+2)

1. PR1 (design) catalogue→schema type module + ADR (placement). _Per-PR review._
2. PR2 (design) kg_writer shared-base decision + ADR (if (ii)). _Per-PR review._
3. PR3 (design) kg_query interface spec (blast-radius/attack-path, 3-hop). _Per-PR review._
4. PR4 (design) findings-as-decorations migration plan + cross-run dedup fix plan.
5. (execution PRs C/D/E land AFTER Stages 1+2 mature — per directive §5.)

## 5. Substrate, invariants, gates

- **Substrate TRIGGER (#48):** the shared type module (3a) + shared kg_writer base (3b) + cross-run dedup (3e) touch charter/shared → **ADRs required (018+) + per-PR review**. Per-agent kg_writer _wiring_ stays per-agent (seal #19 clear). 3-hop cap preserved (P-6). Tenant isolation preserved (ADR-007). Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. The graph turns isolated findings into connected attack-path intelligence (A.4). **Honest:** 3-hop only (deep cascade depth≥5 → v0.5 + Neo4j); graph completeness depends on Stage 1/2 discovery sweeps landing first (Stage 3 _execution_ is gated on them); cross-run dedup is debt to fix here.

## 7. Open decisions (operator)

1. **Shared kg_writer base** — extract (rec) vs keep copy-pattern (ADR-009/010 sealing tension).
2. **Type module placement** — charter vs nexus_runtime vs shared (substrate; ADR).
3. Cross-run dedup fix in v0.4 (rec) or defer.
4. kg_query consumer scope — A.4 Meta-Harness only, or expose to other agents.

## 8. Template note

Same shape as #712 (design variant). HOLD: no execution PRs; Stage 3 execution gated on Stages 1+2.

## 9. Calendar estimate

Design ~1-2 weeks PARALLEL with Stage 1 (Layer 35). Execution ~4-5 weeks AFTER Stages 1+2 (directive §5, Option A). Within the ~22-30w v0.4 envelope.

## 10. Cross-references

- Catalogue (#711): the full node/edge/L-level map + consolidated ownership matrix.
- Directive §5 (Option A) + §9 (ADRs start 018) + P-6 (3-hop). Triggers #29/#48.
- ADRs anticipated: ADR-018+ (type module / shared kg_writer base / cross-run dedup). Related ADR-009 (memory), ADR-007 (tenant isolation).
