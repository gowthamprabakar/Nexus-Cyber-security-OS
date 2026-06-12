"""curiosity v0.2 Task 5 — 14-source registry + per-source bucketing (Q2/WI-X1)."""

from __future__ import annotations

from curiosity.tools.source_agents import (
    SOURCE_AGENTS,
    is_known_source,
    per_source_finding_counts,
)


def test_fourteen_sources() -> None:
    assert len(SOURCE_AGENTS) == 14
    assert "investigation" in SOURCE_AGENTS  # D.7, the newest source
    assert "synthesis" in SOURCE_AGENTS  # D.13


def test_is_known_source() -> None:
    assert is_known_source("cloud_posture")
    assert not is_known_source("curiosity")  # D.12 does not read itself
    assert not is_known_source("nope")


def test_per_source_counts_known_only() -> None:
    rows = [
        {"source_agent": "cloud_posture"},
        {"source_agent": "cloud_posture"},
        {"source_agent": "compliance"},
        {"source_agent": "curiosity"},  # not a known source -> ignored
        {"source_agent": None},  # malformed -> ignored
        {},  # missing -> ignored
    ]
    assert per_source_finding_counts(rows) == {"cloud_posture": 2, "compliance": 1}


def test_per_source_is_breakdown_not_total() -> None:
    rows = [{"source_agent": "audit"}, {"source_agent": "supervisor"}]
    counts = per_source_finding_counts(rows)
    assert counts == {"audit": 1, "supervisor": 1}  # WI-X1: separate, not summed
