"""D.15 v0.2 Task 4 — region-scoping precedence tests (Pattern C, in-package)."""

from __future__ import annotations

from multi_cloud_posture.region_scope import parse_regions_csv, resolve_scan_regions


def test_explicit_regions_win() -> None:
    assert resolve_scan_regions(["eastus"], ["westus", "centralus"]) == ["eastus"]


def test_discovered_used_when_no_explicit() -> None:
    assert resolve_scan_regions(None, ["westus", "centralus"]) == ["westus", "centralus"]


def test_empty_explicit_falls_through_to_discovered() -> None:
    assert resolve_scan_regions([], ["westus"]) == ["westus"]


def test_fallback_when_neither() -> None:
    assert resolve_scan_regions(None, None, fallback=["global"]) == ["global"]


def test_empty_when_nothing_and_no_fallback() -> None:
    assert resolve_scan_regions(None, None) == []


def test_resolve_does_not_alias_input() -> None:
    src = ["eastus"]
    out = resolve_scan_regions(src, None)
    out.append("westus")
    assert src == ["eastus"]  # returned a copy


def test_parse_csv_basic() -> None:
    assert parse_regions_csv("eastus,westus") == ["eastus", "westus"]


def test_parse_csv_trims_and_drops_empties() -> None:
    assert parse_regions_csv(" eastus , , westus ,") == ["eastus", "westus"]


def test_parse_csv_dedupes_preserving_order() -> None:
    assert parse_regions_csv("eastus,westus,eastus") == ["eastus", "westus"]


def test_parse_csv_none_or_blank_is_none() -> None:
    assert parse_regions_csv(None) is None
    assert parse_regions_csv("") is None
    assert parse_regions_csv("   ") is None
    assert parse_regions_csv(" , , ") is None
