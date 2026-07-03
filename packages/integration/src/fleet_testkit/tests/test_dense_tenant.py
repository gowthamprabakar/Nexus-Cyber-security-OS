"""v0.5 Item 2 — the dense-tenant generator plants findable deep chains + noise."""

import pytest
from meta_harness.path_engine import find_generic_paths

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.dense_tenant import plant_dense_tenant


@pytest.mark.asyncio
async def test_planted_deep_paths_are_findable_at_matching_depth() -> None:
    t = "dense"
    async with in_memory_semantic_store() as store:
        info = await plant_dense_tenant(store, t, breadth=3, depth=4, noise=5)
        assert len(info["planted_sinks"]) == 3
        deep = await find_generic_paths(store, t, max_depth=4)
        found = {p.sink_id for p in deep}
        assert set(info["planted_sinks"]) <= found  # all 3 depth-4 sinks reached at depth 4


@pytest.mark.asyncio
async def test_deep_paths_are_missed_below_their_depth() -> None:
    t = "dense-shallow"
    async with in_memory_semantic_store() as store:
        info = await plant_dense_tenant(store, t, breadth=3, depth=4, noise=0)
        shallow = await find_generic_paths(store, t, max_depth=2)
        found = {p.sink_id for p in shallow}
        assert not (set(info["planted_sinks"]) & found)  # depth-4 sinks unreachable in 2 hops
