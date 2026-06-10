"""Tests for the hoisted live-eval lane gating contract (Pattern D, Task 3)."""

from __future__ import annotations

import pytest
from charter import live_skip_reason, nexus_live_enabled

_SETUP = "set NEXUS_LIVE_X=1 and configure creds. e.g.: NEXUS_LIVE_X=1 uv run pytest ..."


def test_enabled_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_X", raising=False)
    assert nexus_live_enabled("NEXUS_LIVE_X") is False


def test_enabled_true_only_for_exactly_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_X", "1")
    assert nexus_live_enabled("NEXUS_LIVE_X") is True
    monkeypatch.setenv("NEXUS_LIVE_X", "true")
    assert nexus_live_enabled("NEXUS_LIVE_X") is False
    monkeypatch.setenv("NEXUS_LIVE_X", "0")
    assert nexus_live_enabled("NEXUS_LIVE_X") is False


def test_skip_reason_returns_setup_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_X", raising=False)
    assert live_skip_reason("NEXUS_LIVE_X", "AWS", _SETUP, lambda: (True, "")) == _SETUP


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_X", "1")
    assert live_skip_reason("NEXUS_LIVE_X", "AWS", _SETUP, lambda: (True, "")) is None


def test_skip_reason_none_when_enabled_and_no_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_X", "1")
    assert live_skip_reason("NEXUS_LIVE_X", "AWS", _SETUP) is None


def test_skip_reason_formats_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_X", "1")
    out = live_skip_reason("NEXUS_LIVE_X", "Azure", _SETUP, lambda: (False, "ClientAuthError"))
    assert out == f"NEXUS_LIVE_X=1 set but Azure is unreachable (ClientAuthError). {_SETUP}"


def test_unreachable_reason_is_secret_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_X", "1")
    # The probe is contractually responsible for a secret-free reason; the
    # formatter passes it through verbatim and adds no secret material.
    out = live_skip_reason(
        "NEXUS_LIVE_X", "ECR", _SETUP, lambda: (False, "EndpointConnectionError")
    )
    assert out is not None and "EndpointConnectionError" in out


def test_lanes_gate_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_A", "1")
    monkeypatch.delenv("NEXUS_LIVE_B", raising=False)
    assert nexus_live_enabled("NEXUS_LIVE_A") is True
    assert nexus_live_enabled("NEXUS_LIVE_B") is False
