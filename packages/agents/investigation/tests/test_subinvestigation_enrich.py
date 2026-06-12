"""investigation v0.2 Task 7 — timeline + ioc_pivot enhancement tests."""

from __future__ import annotations

from investigation.subinvestigations.enrich import (
    extract_supplementary_hashes,
    order_timeline,
)


def test_order_timeline_by_timestamp() -> None:
    events = [
        {"emitted_at": "2026-06-01T00:02:00Z", "correlation_id": "c2"},
        {"emitted_at": "2026-06-01T00:01:00Z", "correlation_id": "c1"},
    ]
    ordered = order_timeline(events)
    assert [e["correlation_id"] for e in ordered] == ["c1", "c2"]


def test_order_timeline_tie_break_by_correlation() -> None:
    events = [
        {"emitted_at": "2026-06-01T00:01:00Z", "correlation_id": "cZ"},
        {"emitted_at": "2026-06-01T00:01:00Z", "correlation_id": "cA"},
    ]
    ordered = order_timeline(events)
    assert [e["correlation_id"] for e in ordered] == ["cA", "cZ"]


def test_order_timeline_time_field_fallback() -> None:
    events = [{"time": "2026-06-01T00:02:00Z"}, {"time": "2026-06-01T00:01:00Z"}]
    ordered = order_timeline(events)
    assert ordered[0]["time"] < ordered[1]["time"]


def test_order_timeline_empty() -> None:
    assert order_timeline([]) == ()


def test_extract_md5() -> None:
    h = "d41d8cd98f00b204e9800998ecf8427e"  # 32 hex
    assert extract_supplementary_hashes(f"hash {h} found")["md5"] == (h,)


def test_extract_sha1() -> None:
    h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40 hex
    assert extract_supplementary_hashes(f"sha1 {h}")["sha1"] == (h,)


def test_no_false_positive_on_clean_text() -> None:
    out = extract_supplementary_hashes("no hashes in this sentence at all")
    assert out["md5"] == () and out["sha1"] == ()


def test_dedup_and_sorted() -> None:
    h = "d41d8cd98f00b204e9800998ecf8427e"
    out = extract_supplementary_hashes(f"{h} and again {h}")
    assert out["md5"] == (h,)
