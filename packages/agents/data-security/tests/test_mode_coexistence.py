"""data-security v0.2 Task 18 — continuous + heartbeat coexistence tests (WI-S11)."""

from __future__ import annotations

from data_security.continuous.mode import (
    DEFAULT_MODE,
    MonitoringMode,
    classify_for_mode,
    modes_coexist,
    select_mode,
)


def test_default_is_heartbeat() -> None:
    assert DEFAULT_MODE == MonitoringMode.HEARTBEAT
    assert select_mode({}) == MonitoringMode.HEARTBEAT


def test_select_continuous() -> None:
    assert select_mode({"data_security_monitoring_mode": "continuous"}) == MonitoringMode.CONTINUOUS


def test_select_case_insensitive() -> None:
    assert select_mode({"data_security_monitoring_mode": "CONTINUOUS"}) == MonitoringMode.CONTINUOUS


def test_invalid_falls_back() -> None:
    assert select_mode({"data_security_monitoring_mode": "bogus"}) == DEFAULT_MODE


def test_modes_coexist() -> None:
    assert modes_coexist() is True


def test_both_modes_equivalent_results() -> None:
    # The defining coexistence property: identical input -> identical classification.
    text = "patient SSN 123-45-6789"
    hb = classify_for_mode(MonitoringMode.HEARTBEAT, text)
    cont = classify_for_mode(MonitoringMode.CONTINUOUS, text)
    assert hb == cont
    assert hb.is_sensitive is True


def test_equivalent_for_clean_text() -> None:
    hb = classify_for_mode(MonitoringMode.HEARTBEAT, "clean")
    cont = classify_for_mode(MonitoringMode.CONTINUOUS, "clean")
    assert hb == cont and hb.is_sensitive is False
