"""D.2 v0.2 Task 16 — NEXUS_LIVE_IDENTITY_AWS lane gating (deterministic, no live AWS).

Exercises the lane's consumption of the hoisted charter Pattern D; the reachability
probe is monkeypatched so these run in CI without credentials.
"""

from __future__ import annotations

from typing import Any

import pytest
from identity import live_lane_aws as lane


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_IDENTITY_AWS", raising=False)
    assert lane.nexus_live_identity_aws_enabled() is False
    # disabled → the skip message is the setup text
    assert lane.aws_skip_reason() == lane.AWS_IDENTITY_LIVE_SETUP


def test_lane_enabled_only_for_exactly_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AWS", "1")
    assert lane.nexus_live_identity_aws_enabled() is True
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AWS", "true")
    assert lane.nexus_live_identity_aws_enabled() is False


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AWS", "1")
    monkeypatch.setattr(lane, "aws_reachable", lambda: (True, ""))
    assert lane.aws_skip_reason() is None


def test_skip_reason_reports_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AWS", "1")
    monkeypatch.setattr(lane, "aws_reachable", lambda: (False, "NoCredentialsError"))
    msg = lane.aws_skip_reason()
    assert msg is not None
    assert "NEXUS_LIVE_IDENTITY_AWS=1 set but AWS IAM is unreachable (NoCredentialsError)" in msg


def test_reachable_probe_is_secret_free(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        def client(self, *_a: Any, **_k: Any) -> Any:
            raise RuntimeError("creds arn:aws:iam::secret request-id=leak")

    monkeypatch.setattr(lane, "CredentialResolver", lambda **_: _Boom())
    ok, reason = lane.aws_reachable()
    assert ok is False
    assert reason == "RuntimeError"  # type name only — no arn / request-id leak


def test_reachable_true_when_sts_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Sts:
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "111122223333"}

    class _Resolver:
        def client(self, service: str) -> _Sts:
            assert service == "sts"
            return _Sts()

    monkeypatch.setattr(lane, "CredentialResolver", lambda **_: _Resolver())
    assert lane.aws_reachable() == (True, "")
