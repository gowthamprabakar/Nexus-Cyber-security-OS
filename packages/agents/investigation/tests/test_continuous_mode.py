"""investigation v0.2 Task 21 — continuous/heartbeat mode coexistence tests (WI-I9/WI-I5)."""

from __future__ import annotations

from datetime import UTC, datetime

from investigation.continuous.mode import (
    DEFAULT_MODE,
    MODE_CONFIG_KEY,
    MonitoringMode,
    emit_for_mode,
    modes_coexist,
    select_mode,
)
from investigation.schemas import (
    Hypothesis,
    IncidentReport,
    Timeline,
)

_TENANT = "01HZX0000000000000000000AA"


def _report() -> IncidentReport:
    return IncidentReport(
        incident_id="inc-1",
        tenant_id=_TENANT,
        correlation_id="corr-1",
        timeline=Timeline(events=()),
        hypotheses=(
            Hypothesis(
                hypothesis_id="h1",
                statement="s",
                confidence=0.5,
                evidence_refs=("finding:f1",),
            ),
        ),
        iocs=(),
        mitre_techniques=(),
        containment_summary="none",
        confidence=0.5,
        emitted_at=datetime(2026, 6, 12, tzinfo=UTC),
    )


def test_default_is_heartbeat() -> None:
    assert DEFAULT_MODE is MonitoringMode.HEARTBEAT


def test_select_missing_defaults_heartbeat() -> None:
    assert select_mode({}) is MonitoringMode.HEARTBEAT


def test_select_continuous() -> None:
    assert select_mode({MODE_CONFIG_KEY: "continuous"}) is MonitoringMode.CONTINUOUS


def test_select_unknown_defaults_heartbeat() -> None:
    assert select_mode({MODE_CONFIG_KEY: "nonsense"}) is MonitoringMode.HEARTBEAT


def test_select_case_insensitive() -> None:
    assert select_mode({MODE_CONFIG_KEY: "CONTINUOUS"}) is MonitoringMode.CONTINUOUS


def test_modes_coexist() -> None:
    assert modes_coexist() is True


def test_emit_is_mode_independent() -> None:
    report = _report()
    heartbeat = emit_for_mode(MonitoringMode.HEARTBEAT, report)
    continuous = emit_for_mode(MonitoringMode.CONTINUOUS, report)
    assert heartbeat == continuous == report.to_ocsf()


def test_emit_is_ocsf_2005() -> None:
    out = emit_for_mode(MonitoringMode.CONTINUOUS, _report())
    assert out["class_uid"] == 2005
