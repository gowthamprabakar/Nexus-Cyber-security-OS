"""synthesis v0.2 Task 12 — stub-LLM eval continuity tests (Q6/WI-Y5)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import synthesis
from synthesis.eval_continuity import (
    STUB_EVAL_CASE_COUNT,
    stub_emission_is_byte_identical,
    stub_lane_active,
)
from synthesis.schemas import ExecutiveSummary, NarrativeSection, SynthesisReport

_EVAL_DIR = Path(synthesis.__file__).resolve().parents[2] / "eval" / "cases"


def _report() -> SynthesisReport:
    return SynthesisReport(
        customer_id="c1",
        run_id="run-7",
        scan_started_at=datetime(2026, 6, 1, tzinfo=UTC),
        scan_completed_at=datetime(2026, 6, 1, 0, 5, tzinfo=UTC),
        executive_summary=ExecutiveSummary(paragraph="x", key_metrics={}),
        sections=[NarrativeSection(heading="H", body="b", cited_finding_ids=[])],
        cited_finding_ids=[],
    )


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_SYNTHESIS", raising=False)


def test_ten_stub_eval_cases() -> None:
    assert STUB_EVAL_CASE_COUNT == 10
    assert len(list(_EVAL_DIR.glob("*.yaml"))) == STUB_EVAL_CASE_COUNT


def test_stub_lane_default_active() -> None:
    # Offline (no live env) -> the deterministic stub lane runs.
    assert stub_lane_active() is True


def test_live_lane_separates_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_SYNTHESIS", "1")
    assert stub_lane_active() is False  # the live lane is a separate path


def test_stub_emission_byte_identical() -> None:
    assert stub_emission_is_byte_identical(_report()) is True
