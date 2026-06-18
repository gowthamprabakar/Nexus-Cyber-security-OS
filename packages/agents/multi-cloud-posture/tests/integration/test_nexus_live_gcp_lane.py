"""D.15 v0.2 Task 14 — NEXUS_LIVE_GCP gated-lane tests + lane independence.

Exercise the lane's env-gating + reachability + skip-message helpers
(`multi_cloud_posture.live_lane_gcp`) and confirm the Azure + GCP lanes are
independent. They do NOT hit GCP — Task 15 owns the real-GCP integration tests.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from eval_framework.cases import load_cases
from multi_cloud_posture.credentials_gcp import GcpCredentialResolver
from multi_cloud_posture.live_lane_azure import nexus_live_azure_enabled
from multi_cloud_posture.live_lane_gcp import (
    gcp_reachable,
    gcp_skip_reason,
    nexus_live_gcp_enabled,
)

_CASES_DIR = Path(__file__).resolve().parents[2] / "eval" / "cases"


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_GCP", raising=False)
    assert nexus_live_gcp_enabled() is False


def test_lane_enabled_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_GCP", "1")
    assert nexus_live_gcp_enabled() is True


def test_skip_reason_when_disabled_has_copy_paste_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_GCP", raising=False)
    reason = gcp_skip_reason()
    assert reason is not None
    assert "NEXUS_LIVE_GCP=1" in reason
    assert "uv run pytest" in reason


def test_reachable_true_when_adc_resolves() -> None:
    with patch.object(
        GcpCredentialResolver, "resolve_credential", return_value=(MagicMock(), "proj")
    ):
        assert gcp_reachable() == (True, "")


def test_reachable_false_with_safe_reason_when_probe_fails() -> None:
    with patch.object(
        GcpCredentialResolver, "resolve_credential", side_effect=ConnectionError("no net")
    ):
        ok, reason = gcp_reachable()
    assert ok is False
    assert reason == "ConnectionError"
    assert "no net" not in reason


def test_skip_reason_when_enabled_but_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_GCP", "1")
    with patch.object(
        GcpCredentialResolver, "resolve_credential", side_effect=ConnectionError("x")
    ):
        reason = gcp_skip_reason()
    assert reason is not None
    assert "unreachable" in reason
    assert "NEXUS_LIVE_GCP=1" in reason


def test_lanes_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Azure and GCP lanes key on distinct env vars and never cross-trigger."""
    # only GCP set
    monkeypatch.setenv("NEXUS_LIVE_GCP", "1")
    monkeypatch.delenv("NEXUS_LIVE_AZURE", raising=False)
    assert nexus_live_gcp_enabled() is True
    assert nexus_live_azure_enabled() is False
    # both set
    monkeypatch.setenv("NEXUS_LIVE_AZURE", "1")
    assert nexus_live_gcp_enabled() is True
    assert nexus_live_azure_enabled() is True


def test_offline_eval_cases_unchanged() -> None:
    assert len(load_cases(_CASES_DIR)) == 10
