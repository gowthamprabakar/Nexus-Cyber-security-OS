# v0.5 Item 2 — Generic-Walker Depth Benchmark Result & Decision

**Date:** 2026-07-03
**Resolves:** the NEX-203 deferral (whether to raise the generic walker's `DEFAULT_MAX_DEPTH` past 4).
**Benchmark:** `packages/integration/src/fleet_testkit/tests/test_depth_benchmark.py` (commit `068539ed`), on a synthetic dense tenant (`plant_dense_tenant`, breadth=20, **depth=6**, noise=200).

## Measured table

```
depth | wall_ms | candidates | deep_recall
    4 |   193.5 |          0 | 0.000
    5 |   198.8 |          0 | 0.000
    6 |   205.4 |         20 | 1.000
    7 |   227.1 |         20 | 1.000
```

(Wall-clock is in-memory SQLite; absolute numbers are not production figures — the _shape_ is what matters.)

## What the benchmark actually measured (and what it did NOT)

**Genuinely measured — these are the real questions:**

1. **No substrate cap.** `walk_paths` accepts `max_depth` 5/6/7 without error. The parked Neo4j/substrate item (spec §5.3 Branch D) is **not** triggered — the recursive-CTE walker handles depth > 4 natively.
2. **Noise does not inflate candidates.** 200 dead-end edges produced **0** junk candidates; the candidate count is exactly the real planted chains (20 at depth ≥6). Walking deeper did not flood the candidate tier with noise.
3. **Cost is modest and graph-size-driven, not depth-dominated.** Wall-clock rose only ~6% depth 4→6 (194→205 ms), ~17% 4→7. The dominant cost driver is graph size, not the depth cap.

**NOT measured — an honest caveat (was overclaimed in an earlier draft):**

4. The recall column is **tautological**, not a measured knee. The fixture plants only **depth-6** chains, so of course recall is 0 below depth 6 and 1.0 at ≥6. Depths 4 and 5 are therefore **measured-identical (both 0)** on this fixture — the benchmark provides **no evidence** that 5 recovers anything 4 misses. "A depth-D chain needs depth-D" is true by construction and tells us nothing about where the _right_ cap is. So this benchmark does **not** identify a measured recall knee for the cap.
5. **Production-scale cost/noise is uncharacterized.** The fixture is ~220 nodes. Frontier growth for deep generic BFS over _all_ source markers on a real 100k-node tenant is the genuine risk, and this benchmark cannot measure it.

## Decision: bump `DEFAULT_MAX_DEPTH` 4 → 5 — a benchmark-_informed judgment_, not a measured knee

The benchmark **rules out** two options with real evidence: **keep-4/substrate/adaptive** are unnecessary (no substrate cap; cost grew ~linearly, so an adaptive cost-bound has no measured trigger). That leaves a **cap choice**, which the recall data (being tautological) does **not** decide. So this is an explicit engineering judgment, informed — but not dictated — by the measured findings:

- **Why raise it at all:** the two measured findings that matter (no noise cliff, modest graph-size-driven cost) show that raising the cap is _safe at this scale_ — there is no cost/noise reason to stay at 4.
- **Why 5 and not 6:** real cloud attack chains commonly run ~4–5 hops (a workload → role → resource → data core, plus one richer leg: stored-secret / cross-account / k8s-escape). 5 is the smallest step that admits those 5-hop chains. Generic-walker deep paths are **exploratory candidates** (scored below every confirmed named archetype), so the _value_ of going deeper is real but bounded, and the **unmeasured** large-graph cost of depth-6 generic BFS is a risk not worth taking on this evidence.
- **This is a judgment, stated plainly:** the fixture does not prove 5 beats 4. The claim rests on the hop-count of real chains, not on a measured recall delta.

## Deferred to v0.6 (honestly)

- **The actual cap (5 vs 6 vs adaptive) at production scale.** Requires a real dense tenant — a `NEXUS_LIVE`-gated real-graph benchmark planting chains of _varied_ depths, so the recall-vs-cost trade-off is genuinely measured (not tautological). If cost proves super-linear there, an **adaptive cap** (`max_depth = f(node_count)`) becomes the v0.6 refinement; the harness (`plant_dense_tenant` + the sweep) is already in place to drive it.

## Verification

After the bump, the full `meta-harness` + `fleet_testkit` suites stay green (no test depended on depth-4-specific candidate counts).
