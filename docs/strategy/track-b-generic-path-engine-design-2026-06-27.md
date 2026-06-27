# Track B Design — the generic attack-path engine

**Date:** 2026-06-27 · **Status:** ✅ COMPLETE (B1–B5 built). Facts grounded in repo at `fleet-test-l2-evaluator`. Prereq: Track A complete (the graph now spans 9 node-type domains, ~20 live edge types).

> **✅ TRACK B BUILT (commits c3bd945 B1, 3f58366 B2, 5c82db7 B3+B4, fe535eb B5).** Decisions locked & implemented: **hybrid** (named = confirmed tier untouched; generic = additive candidate tier), **depth** (prove at 3, discovery at 4 measured), **audience** internal-first, **scoring** heuristic-now (capped). `meta_harness.path_taxonomy` (declarative source/sink/edge model, proven to express all 10 exposure→impact archetypes) + `meta_harness.path_engine` (`find_generic_paths` multi-source BFS, `find_candidate_paths` = novel-only + scored + deduped) + `attack_path_report.render_candidates` (distinct UNVERIFIED tier). e2e proves confirmed + candidate tiers coexist and stay separated; candidates always score below confirmed. The generic engine surfaces the unnamed source→impact combinations (e.g. `runtime_detection → sensitive_data`, `external_identity → known_vulnerability`) as a "what to name next" backlog.

## 0. Thesis (the one decision that shapes everything)

**The generic engine is a DISCOVERY layer over the named archetypes, NOT a replacement.** The 13 named detectors are the product's explainable, curated-severity, remediation-bearing core — we deliberately invested in grouping, subsumption, scoring, remediation, and render for them. A generic walker that re-discovers those same paths adds nothing and _loses_ explainability + scoring. Its unique value is finding the **unanticipated** source→impact path that no named detector covers — the real "Wiz-class" combination — and surfacing it as a lower-confidence **candidate** ("here's a path we don't have a name for yet").

So: **named archetypes = the "confirmed" tier (unchanged); the generic engine = an additive "candidate" tier.** This is also the safest design — it cannot regress the working product; it only adds.

## 1. What exists (facts, file:line)

- `KgQuery.attack_path(src, dst, edge_types, max_depth=3)` (`kg_query.py:281`) — a depth-bounded BFS returning all simple paths between **one** src and **one** dst. Tested, **unused in production**.
- `KgQuery.blast_radius(entity_id, edge_types, depth=3)` — downstream reachable nodes. Unused.
- Substrate (`charter/memory/semantic.py`): `get_relationships_from` (single-hop outgoing), `neighbors` (multi-hop BFS, in-Python, `MAX_TRAVERSAL_DEPTH=3`). Postgres recursive-CTE is "Phase 1b, not implemented."
- The 13 named detectors are each a **(source-marker, edge-path, sink-marker) triple** — the source/sink markers are inline `if` checks (`is_public`, `external_trust`, `privileged`, `_SECRET_DATA_TYPES`, …) and the edge-path is hardcoded.
- Grouping + subsumption + per-archetype severities + remediation + render: already built in `attack_paths.py` / `attack_path_report.py` / `attack_path_remediation.py`.
- ~70 `EdgeType` values defined; **~20 are actually written** by feeders + the four Track-A resolvers.

## 2. The model the engine needs — all EXTRACTABLE from the existing detectors

Three declarative taxonomies, derived by reading the markers already encoded in the 13 detectors:

**Sources (an attack starts here):** `is_public=True` · `external_trust=True` · IAM/GCP public member · `privileged=True` (K8s) · a network-endpoint that `MATCHES_INDICATOR` a malicious IOC · a `PROCESS_EVENT`/`FILE_INTEGRITY_EVENT` (active runtime detection) · an `EXPOSES_MODEL`→internet AI service · an `IAC_ARTIFACT` (a misconfig).

**Sinks (impact lands here):** `DATA_CLASSIFICATION` with a sensitive `data_type` · `CVE_FINDING` · (later: KMS keys, secrets).

**Traversable (attack-progressing) edges — the ~20 live ones, with direction:** `HAS_ACCESS_TO`, `ASSUMES`, `RUNS_IMAGE`, `VULNERABLE_TO`, `EXPOSES_DATA`, `CONTAINS`, `EXPOSES_MODEL`, `OWNED_BY`, `COMMUNICATES_WITH`, `MATCHES_INDICATOR`, `EXECUTED_ON`, `DEPLOYED_VIA`, `DEFINED_IN`. **NOT traversable** (not attack progression): `AFFECTS`, `MAPS_TO_REQUIREMENT`, `REMEDIATES`, `SATISFIES`/`VIOLATES`, audit/compliance edges.

**B1 proves the model is sufficient:** a test that every one of the 13 named archetypes' (source→sink) shape is expressible in these taxonomies. If it isn't, the taxonomy is wrong — fix it before building the walker.

## 3. The engine (algorithm)

1. Enumerate **source** nodes (any node matching a source marker).
2. **Multi-source bounded BFS** over traversable edges (depth ≤ 3, maybe 4) to any **sink** node.
3. Emit each discovered source→sink path (the node+edge chain).

`attack_path()` is point-to-point, so B2 either (a) runs it per (source, sink) pair — simple, fine at current graph sizes — or (b) adds one multi-source walker. Start with (a); optimize only if a real tenant graph makes it slow.

## 4. Scoring (the honest-hard part)

Generic paths can't borrow the curated per-archetype severities. A **composable heuristic**: `score = f(source_severity, sink_severity, path_length_decay, edge_risk)` — explicitly a heuristic, lower-confidence than named. **Cap every generic candidate's score below the lowest named archetype**, so a named finding always outranks a generic candidate. We do NOT pretend the heuristic is as trustworthy as the curated severities — candidates are labeled "candidate," not given a false-precision number.

## 5. Novelty filter (the key to actual value)

For each discovered path, compute its **signature** = (source-type, sink-type, ordered edge-types). If the signature matches any named archetype → **drop it** (the named detector already reports it, better). If no named archetype covers it → it's **novel** → surface as a candidate. This is the _completeness-critic_ role: the generic engine's output is literally a list of "attack paths you have no name for yet" — which doubles as the backlog of what named archetype to build next.

## 6. Explainability

Render a candidate as the labeled hop chain: `Public bucket "x" —EXPOSES_DATA→ ssn  ←HAS_ACCESS_TO— role "r" ←ASSUMES— workload "w" (runtime-exploited)`. Each hop carries the node label + edge. Confidence shown as **candidate** vs the named tier's **confirmed**. A visually distinct "Candidate paths (unverified)" section in the report — never mixed into the prioritized confirmed list.

## 7. Risks + mitigations

| Risk                    | Mitigation                                                                                                                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Combinatorial explosion | depth cap 3–4; start only at sources, end only at sinks; per-tenant node-count guard; cap candidates surfaced (e.g. top 20) and `log` the truncation |
| Nonsense paths          | traverse only attack-progressing edges, directional; require source-marker start + sink-marker end                                                   |
| Explainability loss     | hybrid (named stay named); candidate tier; labeled hops                                                                                              |
| Scoring not credible    | heuristic clearly labeled "candidate"; capped below named; no false-precision                                                                        |
| Substrate cost          | in-Python BFS at depth 3 over a per-tenant graph is fine now; Postgres recursive-CTE is the deferred scale path                                      |

## 8. Build plan (incremental, each CI-REAL)

- **B1 — taxonomy:** declarative source/sink/traversable-edge sets + a test proving all 13 named archetypes' shapes are expressible. (No walker yet.)
- **B2 — walker:** multi-source bounded BFS → sink; test it re-discovers a known named path on a scene (proves traversal correctness).
- **B3 — scoring + candidate tier:** composable score, capped below named; a `confidence` field on `AttackPath`.
- **B4 — novelty filter:** drop signatures covered by a named archetype; keep only novel paths.
- **B5 — wire + prove:** a "candidate paths" section in the report; run on the whole-environment scene with a **deliberately-unnamed planted path** → assert the engine surfaces it as a candidate AND does not duplicate any named archetype.

## 9. Decisions

1. **Hybrid vs replacement — ✅ LOCKED: HYBRID.** Named archetypes stay the "confirmed" tier untouched; the generic engine is an additive "candidate" discovery tier. Additive, can't regress the working product; replacement would throw away the curated severities / named explainability / remediation for no gain.
2. **Depth cap — ✅ MEASURED: keep 3.** Originally assumed novel value lived at depth 4. Measured 3-vs-4 on a graph with transitive 4-hop chains: **identical candidate sets.** Reason — novelty is `(source, sink)`-pair based and _any identity is a source_, so a far 4-hop chain almost always has a closer intermediate source reaching the same sink in fewer hops, and that pair is usually already named. The pair set saturates at low depth, so depth 4 = no novel gain + more cost. The walker is depth-`max_depth` (its own loop over single-hop `get_relationships_from`, NOT the substrate's capped `neighbors`/`attack_path`), so depth is a free param if a future pair-independent novelty model ever wants it.
3. **Audience** — (open) customer-facing "novel paths, review these" vs internal "what to name next" first.
4. **Scoring** — (open) heuristic-now (labeled) vs unranked-until-labeled-dataset.
5. **Sequence** — ✅ start B1 now (depth-independent, valuable regardless: it proves the taxonomy expresses every named archetype).

---

### Reference (verified)

- `kg_query.py:281` `attack_path` (the unused BFS primitive) · `:256` `blast_radius`
- `charter/memory/semantic.py` `get_relationships_from` / `neighbors` (depth cap 3)
- `attack_paths.py` — the 13 named detectors + grouping/subsumption/scoring (the "confirmed" tier to preserve)
- `graph_types.py` `EdgeType` — the ~70-value traversal vocabulary (~20 live)
- `docs/strategy/detection-combination-plan-2026-06-27.md` — Track A (complete) + the A-enables-B rationale
