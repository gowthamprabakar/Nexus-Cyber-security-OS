"""F.3 v0.2 Task 6 — NEXUS_LIVE_AWS=1 gated-lane tests (the gating logic only).

These exercise the lane's env-gating + reachability + skip-message helpers
(`cloud_posture.live_lane`). They do NOT hit AWS — Task 7 owns the real-AWS
integration tests.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from cloud_posture.credentials import CredentialResolver
from cloud_posture.live_lane import aws_reachable, aws_skip_reason, nexus_live_aws_enabled
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[2] / "eval" / "cases"


# ---------------------- env gating ------------------------------------------


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_AWS", raising=False)
    assert nexus_live_aws_enabled() is False


def test_lane_enabled_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AWS", "1")
    assert nexus_live_aws_enabled() is True


def test_skip_reason_when_disabled_has_copy_paste_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_AWS", raising=False)
    reason = aws_skip_reason()
    assert reason is not None
    assert "NEXUS_LIVE_AWS=1" in reason  # actionable setup in the skip message
    assert "uv run pytest" in reason


# ---------------------- reachability probe (STS, Task 3 mechanism) ----------


def test_reachable_true_when_sts_succeeds() -> None:
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "999988887777"}
    with patch.object(CredentialResolver, "client", return_value=sts):
        assert aws_reachable() == (True, "")


def test_reachable_false_with_safe_reason_when_sts_fails() -> None:
    err = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "creds AKIAEXAMPLE denied"}},
        "GetCallerIdentity",
    )
    with patch.object(CredentialResolver, "client", side_effect=err):
        ok, reason = aws_reachable()
    assert ok is False
    assert reason == "ClientError"  # type name only
    assert "AKIAEXAMPLE" not in reason  # no secret material
    assert "Traceback" not in reason


def test_skip_reason_when_enabled_but_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AWS", "1")
    with patch.object(CredentialResolver, "client", side_effect=ConnectionError("no net")):
        reason = aws_skip_reason()
    assert reason is not None
    assert "unreachable" in reason
    assert "NEXUS_LIVE_AWS=1" in reason


# ---------------------- offline lane untouched ------------------------------


def test_offline_eval_cases_unchanged() -> None:
    """The 10 offline eval cases remain the deterministic gate — the new live
    lane does not perturb them."""
    assert len(load_cases(_CASES_DIR)) == 10
