# Track B to Production — what it actually takes

**Date:** 2026-06-28. Track B (the generic attack-path engine) is the real lever toward Wiz-scale
path discovery — path count becomes _data-driven_ (like Wiz's security graph) instead of capped at
our hand-built archetype vocabulary. Today it's a working _seed_; this is the gap to production.

## What "production" means here

A customer connects an account and, alongside the confirmed named findings, sees a **reviewed,
scored, explained list of attack paths the graph found that no named detector covers** — and the
ones they confirm become named detectors (the loop that grows the product without hand-guessing).

## Current state (the seed, shipped B1–B5)

| Piece          | Now                                                                                          | Limit                                                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Novelty        | (source-marker, sink-marker) **pair**-based                                                  | too coarse — drops every new _route_ between an already-named pair, so depth-4 transitive chains never surface                       |
| Depth          | 3                                                                                            | measured: pair-novelty saturates at 3, so depth 4 added nothing — but that's a _consequence of_ the coarse novelty, not a real limit |
| Scoring        | heuristic (source×sink weight, length decay), capped below named                             | not calibrated; no exploitability / reachability / sensitivity signal                                                                |
| Explainability | markers + edge signature ("runtime_detection → sensitive_data via EXECUTED_ON/EXPOSES_DATA") | no node labels, no per-hop reason — reads like IDs, not a story                                                                      |
| Audience       | internal-only candidate tier                                                                 | no customer surface, no analyst feedback loop                                                                                        |
| Substrate      | in-Python BFS, per-source, depth 3                                                           | no Postgres recursive CTE; won't scale to large tenant graphs                                                                        |
| Taxonomy       | ~8 sources / 2 sinks / ~13 edges                                                             | misses KMS, secrets, SaaS, network — engine is blind to graph it can't mark                                                          |

## The production gap (BP1–BP8)

- **BP1 — richer novelty (the keystone). ✅ DONE (2026-06-28, commit 7021470).** Replaced pair-based with **(source, sink, edge-signature)** novelty (a new _route_ is novel even between a named pair). Added a precision guard the seed lacked: a novel-shaped route between two nodes a named shape ALREADY connects (a redundant parallel edge, e.g. a public bucket's `CONTAINS` beside its named `EXPOSES_DATA`) is suppressed by node-pair coverage — new routes to NEW impacts surface, duplicates of a named endpoint pair don't. `NAMED_SHAPES` is pinned against the named-archetype model by a taxonomy test so they can't drift. This is what makes depth 4+ pay off — transitive privilege chains, lateral movement, multi-domain hops become discoverable. Everything else depends on this.
- **BP2 — real scoring. ✅ DONE (2026-06-28, commit a2e72ba).** Four credible signals in [0,1], multiplied + capped below every confirmed severity: source exposure weight, sink impact (CVE severity x KEV boost, or data sensitivity for regulated/credential types), weakest-edge progression risk (a chain is as strong as its least-certain hop), and length decay. Sink signal captured for free at the walk. Calibration against a labeled scene set remains BP8.
- **BP3 — explainable render. ✅ DONE (2026-06-28, commit ba9dc95).** A candidate now reads as one English sentence — node external_ids resolved to labels + per-hop edge verbs ("Active runtime detection `…` executed on `host-1`, which exposes `customers.csv` (sensitive data)"). The raw shape stays a secondary line (the dedup/promote key). Labels captured for free during the walk, so render stays pure.
- **BP4 — customer surface + feedback loop. ✅ DONE (2026-06-28, commit 947e37f).** `candidate_feedback` adds the analyst loop on the candidate tier (BP3 render is the panel). A candidate's signature `(source, sink, edge-signature)` is the stable key. **dismiss → suppress**: `FeedbackLog` records the shape; `find_candidate_paths` / `analyze` take `suppressed=…` and drop every candidate of it. **confirm → auto-draft**: `draft_archetype` emits a reviewable named-detector draft — suggested name/severity, the `NAMED_SHAPES` entry that retires it, a kg_query detector sketch walking the actual signature, and the exact slice checklist. Auto-drafted, not auto-merged. `FeedbackLog` is serializable so BP7 can persist decisions.
- **BP5 — scale substrate.** Postgres **recursive CTE** for the walk (the deferred "Phase 1b"), per-tenant node-count guards, result caching — seconds on real-size graphs.
- **BP6 — taxonomy breadth.** Add sources/sinks as feeders grow (KMS keys, secrets, SaaS identities, network reachability) so the engine sees the whole graph, not 6 domains.
- **BP7 — continuous run.** Wire into the scan loop (`analyze()` already returns candidates); persist per scan, **diff across runs** (new path appeared → alert).
- **BP8 — validation harness. ✅ DONE (2026-06-28, commit 9df7247).** Six realistic multi-domain scenes with known ground truth (4 plant a novel path the engine must surface — runtime->data, privileged-pod->data, transitive public->data, external assume-chain->data; 2 must stay clean — named-only, redundant parallel edge). Measures candidate precision + recall across the set, pinned at 1.0 so a missed novel path or spurious candidate fails loudly. Extensible as the generic-engine scorecard. (Done before BP4 so the feedback loop builds on a measured base.)

## Sequence

BP1 (novelty) → BP3 (render) → BP2 (scoring) → BP8 (measure precision) → BP4 (feedback loop) → BP6 (taxonomy as feeders land) → BP5 (CTE, only when graph size demands) → BP7 (continuous).

BP1 is the keystone and is depth-independent of the rest — it alone unlocks the discovery value the seed can't reach today.

## Honest framing

This is the **scale** answer (data-driven path count). The named archetypes stay the **explainable, high-precision headline** (and the confirm-loop in BP4 keeps growing them from candidates). Neither replaces the other; production Track B is what stops the path count being capped by how many patterns we hand-write.
