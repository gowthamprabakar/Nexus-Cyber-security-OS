"""v0.5 Item 2 — depth sweep: does raising the generic-walker cap pay for its cost/noise?

Prints a table (wall-clock, candidate count = noise proxy, planted-deep-path recall) across depths
4-7 on one dense tenant. Asserts the harness runs and recall reaches 1.0 once depth >= the planted
chain length. The DECISION (keep/bump/adaptive) is Task 9, from these numbers.
"""

import time

import pytest
from meta_harness.path_engine import find_candidate_paths, find_generic_paths

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.dense_tenant import plant_dense_tenant


@pytest.mark.asyncio
async def test_depth_sweep_prints_table_and_recalls_deep_paths() -> None:
    t = "bench"
    async with in_memory_semantic_store() as store:
        info = await plant_dense_tenant(store, t, breadth=20, depth=6, noise=200)
        planted = set(info["planted_sinks"])
        rows = []
        recall_at_6 = 0.0
        for d in (4, 5, 6, 7):
            t0 = time.perf_counter()
            paths = await find_generic_paths(store, t, max_depth=d)
            cands = await find_candidate_paths(store, t, max_depth=d, limit=10_000)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            recall = len(planted & {p.sink_id for p in paths}) / len(planted)
            rows.append((d, round(elapsed_ms, 1), len(cands), round(recall, 3)))
            if d == 6:
                recall_at_6 = recall
        print("\n=== DEPTH BENCHMARK (breadth=20 depth=6 noise=200) ===")
        print("depth | wall_ms | candidates | deep_recall")
        for d, ms, nc, rc in rows:
            print(f"{d:5d} | {ms:7.1f} | {nc:10d} | {rc:.3f}")
        assert recall_at_6 == 1.0  # a depth-6 chain must be fully recalled once depth >= 6
