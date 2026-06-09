"""D.5 v0.2 Task 13 — NEXUS_LIVE_AZURE gated-lane tests (gating logic only).

Exercise the lane's env-gating + reachability + skip-message helpers
(`multi_cloud_posture.live_lane_azure`). They do NOT hit Azure — Task 15 owns the
real-Azure integration tests.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from eval_framework.cases import load_cases
from multi_cloud_posture.credentials_azure import AzureCredentialResolver
from multi_cloud_posture.live_lane_azure import (
    azure_reachable,
    azure_skip_reason,
    nexus_live_azure_enabled,
)

_CASES_DIR = Path(__file__).resolve().parents[2] / "eval" / "cases"


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_AZURE", raising=False)
    assert nexus_live_azure_enabled() is False


def test_lane_enabled_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AZURE", "1")
    assert nexus_live_azure_enabled() is True


def test_skip_reason_when_disabled_has_copy_paste_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_AZURE", raising=False)
    reason = azure_skip_reason()
    assert reason is not None
    assert "NEXUS_LIVE_AZURE=1" in reason
    assert "uv run pytest" in reason


def test_reachable_true_when_subscriptions_list() -> None:
    client = MagicMock()
    client.subscriptions.list.return_value = [MagicMock(subscription_id="sub-1")]
    with patch.object(AzureCredentialResolver, "client", return_value=client):
        assert azure_reachable() == (True, "")


def test_reachable_false_with_safe_reason_when_probe_fails() -> None:
    with patch.object(AzureCredentialResolver, "client", side_effect=ConnectionError("no net")):
        ok, reason = azure_reachable()
    assert ok is False
    assert reason == "ConnectionError"
    assert "no net" not in reason


def test_skip_reason_when_enabled_but_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AZURE", "1")
    with patch.object(AzureCredentialResolver, "client", side_effect=ConnectionError("x")):
        reason = azure_skip_reason()
    assert reason is not None
    assert "unreachable" in reason
    assert "NEXUS_LIVE_AZURE=1" in reason


def test_offline_eval_cases_unchanged() -> None:
    """The 10 offline eval cases stay the deterministic gate — the live lane does
    not perturb them."""
    assert len(load_cases(_CASES_DIR)) == 10
