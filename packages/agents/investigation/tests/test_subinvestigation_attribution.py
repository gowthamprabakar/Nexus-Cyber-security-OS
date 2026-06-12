"""investigation v0.2 Task 8 — asset_enum + attribution enhancement tests (H5)."""

from __future__ import annotations

from investigation.subinvestigations.attribution import (
    enumerate_assets,
    score_attribution,
)


def test_enumerate_assets_within_depth() -> None:
    nodes = [
        {"entity_id": "host-1", "type": "host", "depth": 1},
        {"entity_id": "host-2", "type": "host", "depth": 2},
    ]
    assert enumerate_assets(nodes, requested_depth=3) == ("host-1", "host-2")


def test_enumerate_assets_depth_capped() -> None:
    # nodes beyond the H5 cap (3) are dropped even if requested_depth is higher.
    nodes = [
        {"entity_id": "near", "type": "host", "depth": 3},
        {"entity_id": "far", "type": "host", "depth": 4},
    ]
    assert enumerate_assets(nodes, requested_depth=10) == ("near",)


def test_enumerate_assets_dedup() -> None:
    nodes = [
        {"entity_id": "h", "type": "host", "depth": 1},
        {"entity_id": "h", "type": "host", "depth": 2},
    ]
    assert enumerate_assets(nodes, requested_depth=3) == ("h",)


def test_enumerate_assets_empty() -> None:
    assert enumerate_assets([], requested_depth=3) == ()


def test_score_attribution_confidence() -> None:
    scores = score_attribution({"T1078": 3, "T1059": 1})
    by_id = {s.technique_id: s.confidence for s in scores}
    assert by_id["T1078"] == 1.0 and by_id["T1059"] == round(1 / 3, 3)


def test_score_attribution_ranked_desc() -> None:
    scores = score_attribution({"T1059": 1, "T1078": 3})
    assert [s.technique_id for s in scores] == ["T1078", "T1059"]


def test_score_attribution_saturates() -> None:
    [s] = score_attribution({"T1078": 99})
    assert s.confidence == 1.0


def test_score_attribution_empty() -> None:
    assert score_attribution({}) == ()
