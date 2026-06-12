"""synthesis v0.2 Task 14 — continuous + heartbeat coexistence tests (Q7)."""

from __future__ import annotations

from datetime import UTC, datetime

from synthesis.continuous.mode import (
    DEFAULT_MODE,
    MonitoringMode,
    emit_for_mode,
    modes_coexist,
    select_mode,
)
from synthesis.schemas import ExecutiveSummary, NarrativeSection, SynthesisReport


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


def test_default_is_heartbeat() -> None:
    assert DEFAULT_MODE == MonitoringMode.HEARTBEAT
    assert select_mode({}) == MonitoringMode.HEARTBEAT


def test_select_continuous() -> None:
    assert select_mode({"synthesis_monitoring_mode": "continuous"}) == MonitoringMode.CONTINUOUS


def test_select_case_insensitive() -> None:
    assert select_mode({"synthesis_monitoring_mode": "CONTINUOUS"}) == MonitoringMode.CONTINUOUS


def test_invalid_falls_back() -> None:
    assert select_mode({"synthesis_monitoring_mode": "bogus"}) == DEFAULT_MODE


def test_modes_coexist() -> None:
    assert modes_coexist() is True


def test_both_modes_equivalent_output() -> None:
    report = _report()
    hb = emit_for_mode(MonitoringMode.HEARTBEAT, report)
    cont = emit_for_mode(MonitoringMode.CONTINUOUS, report)
    assert hb == cont  # mode governs cadence, not rendering
