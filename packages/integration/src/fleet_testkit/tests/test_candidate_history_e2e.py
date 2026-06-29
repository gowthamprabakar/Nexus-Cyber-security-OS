"""BP7 — continuous run: snapshot the candidate tier, diff across scans, alert on new paths."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.candidate_history import (
    CandidateSnapshot,
    diff_candidates,
    render_delta,
    snapshot_candidates,
)
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-bp7"
_R = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_PE = NodeCategory.PROCESS_EVENT.value


async def _n(store, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=_T, entity_type=etype, external_id=ext, properties=props
    )


async def _e(store, src, dst, rel):
    await store.add_relationship(
        tenant_id=_T, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


async def _runtime_to_data(store, host_ext: str) -> None:
    ev = await _n(store, _PE, f"RUNTIME-{host_ext}-e", {"finding_type": "process"})
    host = await _n(store, _R, host_ext, {})
    data = await _n(store, _DC, f"{host_ext}:ssn", {"data_type": "ssn"})
    await _e(store, ev, host, EdgeType.EXECUTED_ON.value)
    await _e(store, host, data, EdgeType.EXPOSES_DATA.value)


@pytest.mark.asyncio
async def test_new_candidate_path_is_alerted_across_scans() -> None:
    async with in_memory_semantic_store() as store:
        # Scan 1: one novel path.
        await _runtime_to_data(store, "host-1")
        scan1 = snapshot_candidates(await find_candidate_paths(store, _T))
        assert len(scan1.keys()) == 1

        # Between scans a second host appears with the same novel shape on different nodes.
        await _runtime_to_data(store, "host-2")
        scan2 = snapshot_candidates(await find_candidate_paths(store, _T))

        delta = diff_candidates(scan1, scan2)
        assert len(delta.new) == 1 and len(delta.persisting) == 1 and not delta.resolved
        # The alert names the NEW path by its real label, not a ULID.
        alert = render_delta(delta, scan2, tenant_id=_T)
        assert "ALERT: 1 new candidate" in alert
        assert "`host-2`" in alert and "`host-1`" not in alert


@pytest.mark.asyncio
async def test_stable_key_across_rebuild_means_no_false_new() -> None:
    # The same real path in two SEPARATE stores (fresh ULIDs) keeps the same key → not "new".
    async with in_memory_semantic_store() as store_a:
        await _runtime_to_data(store_a, "host-1")
        snap_a = snapshot_candidates(await find_candidate_paths(store_a, _T))
    async with in_memory_semantic_store() as store_b:
        await _runtime_to_data(store_b, "host-1")
        snap_b = snapshot_candidates(await find_candidate_paths(store_b, _T))
    delta = diff_candidates(snap_a, snap_b)
    assert not delta.new and not delta.resolved and len(delta.persisting) == 1


def test_snapshot_serialization_round_trips() -> None:
    snap = CandidateSnapshot(entries={"k1": {"score": 30, "story": "s"}})
    assert CandidateSnapshot.from_dict(snap.to_dict()).entries == snap.entries


@pytest.mark.asyncio
async def test_analyze_with_history_is_the_continuous_step() -> None:
    from meta_harness.candidate_history import CandidateSnapshot
    from meta_harness.scan import analyze_with_history

    async with in_memory_semantic_store() as store:
        await _runtime_to_data(store, "host-1")
        # First run: no prior snapshot → everything is new.
        result, snap1, delta1 = await analyze_with_history(
            store, _T, previous=CandidateSnapshot({})
        )
        assert result.candidates and len(delta1.new) == 1

        await _runtime_to_data(store, "host-2")
        # Second run: feed the prior snapshot → only the new host alerts.
        _r2, snap2, delta2 = await analyze_with_history(store, _T, previous=snap1)
        assert len(delta2.new) == 1 and len(delta2.persisting) == 1
        assert len(snap2.keys()) == 2


@pytest.mark.asyncio
async def test_no_new_paths_is_a_clean_line() -> None:
    async with in_memory_semantic_store() as store:
        await _runtime_to_data(store, "host-1")
        snap = snapshot_candidates(await find_candidate_paths(store, _T))
    delta = diff_candidates(snap, snap)
    assert "No new candidate attack paths" in render_delta(delta, snap, tenant_id=_T)
