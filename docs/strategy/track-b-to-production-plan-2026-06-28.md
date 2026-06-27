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

- **BP1 — richer novelty (the keystone).** Replace pair-based with **(source, sink, edge-signature)** novelty (a new _route_ is novel even between a named pair). This is what makes depth 4+ pay off — transitive privilege chains, lateral movement, multi-domain hops become discoverable. Everything else depends on this.
- **BP2 — real scoring.** Per-edge risk weights + exploitability (CVE severity / KEV) + data sensitivity + reachability confidence; calibrate against a labeled scene set. Candidates ranked credibly, still capped below confirmed.
- **BP3 — explainable render.** Resolve node external_ids → labels; per-hop "why" (the marker/edge meaning). A candidate reads as a sentence, not a signature.
- **BP4 — customer surface + feedback loop.** Promote the candidate tier to a reviewed "potential paths" panel; analyst **confirm → auto-draft a named archetype** (the growth loop), **dismiss → suppress signature**. This is how the product grows without hand-guessing patterns.
- **BP5 — scale substrate.** Postgres **recursive CTE** for the walk (the deferred "Phase 1b"), per-tenant node-count guards, result caching — seconds on real-size graphs.
- **BP6 — taxonomy breadth.** Add sources/sinks as feeders grow (KMS keys, secrets, SaaS identities, network reachability) so the engine sees the whole graph, not 6 domains.
- **BP7 — continuous run.** Wire into the scan loop (`analyze()` already returns candidates); persist per scan, **diff across runs** (new path appeared → alert).
- **BP8 — validation harness.** A "planted novel path" suite + **candidate-precision measurement** (of N surfaced candidates, how many are real vs noise) on realistic multi-domain scenes — the generic-engine analogue of the bank scorecard.

## Sequence

BP1 (novelty) → BP3 (render) → BP2 (scoring) → BP8 (measure precision) → BP4 (feedback loop) → BP6 (taxonomy as feeders land) → BP5 (CTE, only when graph size demands) → BP7 (continuous).

BP1 is the keystone and is depth-independent of the rest — it alone unlocks the discovery value the seed can't reach today.

## Honest framing

This is the **scale** answer (data-driven path count). The named archetypes stay the **explainable, high-precision headline** (and the confirm-loop in BP4 keeps growing them from candidates). Neither replaces the other; production Track B is what stops the path count being capped by how many patterns we hand-write.
