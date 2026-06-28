"""BP8 — candidate-precision validation harness for the generic path engine.

The bank scorecard measures the NAMED detectors. This is its generic-engine analogue: a set of
realistic multi-domain scenes with KNOWN ground truth — each plants specific novel paths the engine
SHOULD surface and structures it MUST NOT surface (named-covered shapes, redundant parallel edges).
It then measures candidate precision (of what surfaced, how much was expected) and recall (of what
was planted, how much surfaced) across the set, and pins both at 1.0 so an engine regression — a
missed novel path or a spurious candidate — fails loudly.

Scenes are built directly on the graph (the engine scores whatever is in the graph, regardless of
which feeder wrote it); the novel combinations are, by definition, ones no named feeder produces.
Run with ``-s`` to see the per-scene scorecard.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_R = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_CVE = NodeCategory.CVE_FINDING.value
_ID = NodeCategory.IDENTITY.value
_PE = NodeCategory.PROCESS_EVENT.value
_K8S = NodeCategory.K8S_OBJECT.value

_T = "tenant-bp8"
Shape = tuple[str, str, tuple[str, ...]]


async def _n(store, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=_T, entity_type=etype, external_id=ext, properties=props
    )


async def _e(store, src, dst, rel):
    await store.add_relationship(
        tenant_id=_T, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


# --- Scenes: (name, builder, expected novel shapes) ---------------------------------------------


async def _runtime_to_data(store) -> None:
    """A runtime detection on a host that reaches sensitive data — named runtime only joins vulns."""
    ev = await _n(store, _PE, "RUNTIME-PROC-1-e", {"finding_type": "process"})
    host = await _n(store, _R, "i-host-1", {"kind": "compute"})
    data = await _n(store, _DC, "arn:aws:s3:::pii/cust.csv", {"data_type": "ssn"})
    await _e(store, ev, host, EdgeType.EXECUTED_ON.value)
    await _e(store, host, data, EdgeType.EXPOSES_DATA.value)


async def _privileged_pod_to_data(store) -> None:
    """A privileged pod with access to sensitive data — named privileged only joins vulns."""
    pod = await _n(store, _K8S, "prod/pod/admin", {"privileged": True})
    bucket = await _n(store, _R, "arn:aws:s3:::secrets", {"kind": "bucket"})  # not public
    data = await _n(store, _DC, "arn:aws:s3:::secrets/k", {"data_type": "credentials"})
    await _e(store, pod, bucket, EdgeType.HAS_ACCESS_TO.value)
    await _e(store, bucket, data, EdgeType.EXPOSES_DATA.value)


async def _transitive_public_to_data(store) -> None:
    """BP1: public resource reaches data via a 2-hop CONTAINS/EXPOSES route (named is direct only)."""
    pub = await _n(store, _R, "arn:aws:s3:::front", {"is_public": True})
    mid = await _n(store, _R, "arn:aws:s3:::staging", {})  # non-public → not a source
    data = await _n(store, _DC, "arn:aws:s3:::staging/d", {"data_type": "pci"})
    await _e(store, pub, mid, EdgeType.CONTAINS.value)
    await _e(store, mid, data, EdgeType.EXPOSES_DATA.value)


async def _external_assume_chain(store) -> None:
    """An externally-trusted identity that ASSUMES a role to reach data — a route named trust misses."""
    ext = await _n(store, _ID, "arn:aws:iam::999:role/partner", {"external_trust": True})
    role = await _n(store, _ID, "arn:aws:iam::111:role/app", {})
    bucket = await _n(store, _R, "arn:aws:s3:::data", {})
    data = await _n(store, _DC, "arn:aws:s3:::data/pii", {"data_type": "ssn"})
    await _e(store, ext, role, EdgeType.ASSUMES.value)
    await _e(store, role, bucket, EdgeType.HAS_ACCESS_TO.value)
    await _e(store, bucket, data, EdgeType.EXPOSES_DATA.value)


async def _named_only_public_secret(store) -> None:
    """A public bucket exposing a secret — purely the named public_secret shape. No candidate."""
    b = await _n(store, _R, "arn:aws:s3:::creds", {"is_public": True})
    d = await _n(store, _DC, "arn:aws:s3:::creds/k", {"data_type": "aws_access_key"})
    await _e(store, b, d, EdgeType.EXPOSES_DATA.value)


async def _redundant_parallel_edge(store) -> None:
    """A public bucket carrying both EXPOSES_DATA (named) and a parallel CONTAINS to the SAME data —
    the CONTAINS route is a redundant edge to a named endpoint pair, not a new path. No candidate."""
    b = await _n(store, _R, "arn:aws:s3:::dup", {"is_public": True})
    d = await _n(store, _DC, "arn:aws:s3:::dup/k", {"data_type": "ssn"})
    await _e(store, b, d, EdgeType.EXPOSES_DATA.value)
    await _e(store, b, d, EdgeType.CONTAINS.value)


_SCENES: list[tuple[str, Callable[[object], Awaitable[None]], frozenset[Shape]]] = [
    (
        "runtime -> data",
        _runtime_to_data,
        frozenset({("runtime_detection", "sensitive_data", ("EXECUTED_ON", "EXPOSES_DATA"))}),
    ),
    (
        "privileged pod -> data",
        _privileged_pod_to_data,
        frozenset({("privileged_workload", "sensitive_data", ("HAS_ACCESS_TO", "EXPOSES_DATA"))}),
    ),
    (
        "BP1 transitive public -> data",
        _transitive_public_to_data,
        frozenset({("public_resource", "sensitive_data", ("CONTAINS", "EXPOSES_DATA"))}),
    ),
    (
        "external assume-chain -> data",
        _external_assume_chain,
        frozenset(
            {("external_identity", "sensitive_data", ("ASSUMES", "HAS_ACCESS_TO", "EXPOSES_DATA"))}
        ),
    ),
    ("named-only public secret (no candidate)", _named_only_public_secret, frozenset()),
    ("redundant parallel edge (no candidate)", _redundant_parallel_edge, frozenset()),
]


async def _surfaced_shapes(builder) -> frozenset[Shape]:
    async with in_memory_semantic_store() as store:
        await builder(store)
        cands = await find_candidate_paths(store, _T)
        return frozenset(
            (c.path.source_marker, c.path.sink_marker, c.path.edge_signature) for c in cands
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("name,builder,expected", _SCENES, ids=[s[0] for s in _SCENES])
async def test_scene_surfaces_exactly_its_planted_candidates(name, builder, expected) -> None:
    assert await _surfaced_shapes(builder) == expected, name


@pytest.mark.asyncio
async def test_candidate_precision_scorecard() -> None:
    tp = fp = fn = 0
    rows: list[tuple[str, int, int, int]] = []
    for name, builder, expected in _SCENES:
        got = await _surfaced_shapes(builder)
        s_tp, s_fp, s_fn = len(got & expected), len(got - expected), len(expected - got)
        rows.append((name, s_tp, s_fp, s_fn))
        tp, fp, fn = tp + s_tp, fp + s_fp, fn + s_fn

    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    print("\n=== CANDIDATE PRECISION SCORECARD (generic engine, BP8) ===")
    print(f"  {'scene':42s} {'TP':>3} {'FP':>3} {'FN':>3}")
    for name, s_tp, s_fp, s_fn in rows:
        print(f"  {name:42s} {s_tp:>3} {s_fp:>3} {s_fn:>3}")
    print(f"  {'TOTAL':42s} {tp:>3} {fp:>3} {fn:>3}  precision={precision:.3f} recall={recall:.3f}")

    # Designed scenes with known ground truth: the engine must be exact — a missed planted path
    # (recall < 1) or a spurious candidate (precision < 1) is an engine regression.
    assert fp == 0, f"{fp} spurious candidate(s) surfaced"
    assert fn == 0, f"{fn} planted novel path(s) missed"
    assert precision == 1.0 and recall == 1.0
