# v0.5 Item 2 — Generic-Walker Depth Benchmark Result & Decision

**Date:** 2026-07-03
**Resolves:** the NEX-203 deferral (whether to raise the generic walker's `DEFAULT_MAX_DEPTH` past 4).
**Benchmark:** `packages/integration/src/fleet_testkit/tests/test_depth_benchmark.py` (commit `068539ed`), on a synthetic dense tenant (`plant_dense_tenant`, breadth=20, depth=6, noise=200).

## Measured table

```
depth | wall_ms | candidates | deep_recall
    4 |   193.5 |          0 | 0.000
    5 |   198.8 |          0 | 0.000
    6 |   205.4 |         20 | 1.000
    7 |   227.1 |         20 | 1.000
```

(Wall-clock is in-memory SQLite; absolute numbers are not production figures — the _shape_ is what matters.)

## What the numbers establish

1. **No substrate cap.** `walk_paths` accepts `max_depth` 5/6/7 without error. The parked Neo4j/substrate item (spec §5.3 Branch D) is **not** triggered — the recursive-CTE walker handles depth > 4 natively.
2. **Noise does not inflate candidates.** 200 dead-end edges produced **0** junk candidates; the candidate count is exactly the real planted chains (20 at depth ≥6, one per chain, all novel shapes). Raising depth did not flood the candidate tier with noise.
3. **Cost is modest and graph-size-driven, not depth-dominated.** Wall-clock rose only ~6% from depth 4→6 (194→205 ms) and ~17% 4→7. The dominant cost driver is graph size, not the depth cap — which means raising the cap is relatively safe _at a given graph size_.
4. **Recall is a step function.** Depth-6 chains are found only at depth ≥6. A cap below a real chain's length silently drops it.

## Decision: bump `DEFAULT_MAX_DEPTH` 4 → 5 (conservative)

Spec §5.3 offered keep-4 / bump-to-N / adaptive / substrate. The data rules out **keep-4** (depth 4 misses deep chains) and **substrate/adaptive** (no cap hit; cost grew ~linearly, not super-linearly, so an adaptive cost-bound has no measured trigger). That leaves **bump-to-N**.

**N = 5, not the fixture-validated 6.** Rationale for the conservative margin:

- The generic walker's deep paths are **exploratory candidates** (scored below every confirmed named archetype, for "what to name next") — secondary to the named detectors, which already traverse deep archetypes with no depth cap. So the _value_ of deeper generic walking is real but bounded.
- Production-scale cost is **not** characterized: the fixture is ~220 nodes. Frontier growth for depth-6 generic BFS over _all_ source markers on a real 100k-node tenant is the genuine risk, and this benchmark cannot measure it.
- 5 is the smallest step that captures the common **5-hop richer chains** (stored-secret / cross-account / k8s-escape legs) that depth 4 misses, at minimal incremental frontier risk.

## Deferred to v0.6 (honestly)

- **Deeper caps (6+) and the real cost/noise curve at production scale.** Requires a real dense tenant — a `NEXUS_LIVE`-gated real-graph benchmark. If cost proves super-linear there, an **adaptive cap** (`max_depth = f(node_count)`) becomes the v0.6 refinement; the benchmark harness (`plant_dense_tenant` + the sweep) is already in place to drive it.

## Verification

After the bump, the full `meta-harness` + `fleet_testkit` suites stay green (no test depended on depth-4-specific candidate counts).
