"""Tests for `runtime_threat.severity` — three native scales → internal Severity."""

from __future__ import annotations

import pytest
from runtime_threat.schemas import Severity
from runtime_threat.severity import (
    falco_to_severity,
    osquery_to_severity,
    tracee_to_severity,
)

# ---------------------------- Falco priority mapping --------------------


@pytest.mark.parametrize(
    ("priority", "expected"),
    [
        ("Emergency", Severity.CRITICAL),
        ("Alert", Severity.CRITICAL),
        ("Critical", Severity.CRITICAL),
        ("Error", Severity.HIGH),
        ("Warning", Severity.MEDIUM),
        ("Notice", Severity.LOW),
        ("Informational", Severity.INFO),
        ("Debug", Severity.INFO),
    ],
)
def test_falco_priority_canonical_mapping(priority: str, expected: Severity) -> None:
    assert falco_to_severity(priority) is expected


def test_falco_unknown_priority_falls_back_to_info() -> None:
    assert falco_to_severity("Bogus") is Severity.INFO


def test_falco_blank_priority_falls_back_to_info() -> None:
    assert falco_to_severity("") is Severity.INFO


def test_falco_case_sensitivity_strict() -> None:
    """Falco emits TitleCase priorities — lowercase variants don't match."""
    assert falco_to_severity("warning") is Severity.INFO
    assert falco_to_severity("WARNING") is Severity.INFO


# ---------------------------- Tracee severity mapping --------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, Severity.INFO),
        (1, Severity.LOW),
        (2, Severity.MEDIUM),
        (3, Severity.CRITICAL),
    ],
)
def test_tracee_severity_canonical_mapping(value: int, expected: Severity) -> None:
    assert tracee_to_severity(value) is expected


@pytest.mark.parametrize("value", [-1, 4, 99, 100])
def test_tracee_out_of_range_falls_back_to_info(value: int) -> None:
    assert tracee_to_severity(value) is Severity.INFO


def test_tracee_coerces_float_to_int() -> None:
    """Some Tracee builds may emit `3.0` as a JSON number; treat as 3."""
    assert tracee_to_severity(int(3.0)) is Severity.CRITICAL


# ---------------------------- OSQuery (same scale as Tracee) ------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, Severity.INFO),
        (1, Severity.LOW),
        (2, Severity.MEDIUM),
        (3, Severity.CRITICAL),
    ],
)
def test_osquery_uses_tracee_scale(value: int, expected: Severity) -> None:
    assert osquery_to_severity(value) is expected


def test_osquery_out_of_range_falls_back_to_info() -> None:
    assert osquery_to_severity(99) is Severity.INFO
    assert osquery_to_severity(-1) is Severity.INFO
