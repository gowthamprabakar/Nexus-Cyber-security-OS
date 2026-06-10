"""D.2 v0.2 Task 17 — NEXUS_LIVE_IDENTITY_AZURE lane gating (deterministic, no live Azure).

Exercises the lane's consumption of the hoisted charter Pattern D; the reachability
probe is monkeypatched so these run in CI without Azure credentials.
"""

from __future__ import annotations

from typing import Any

import pytest
from identity import live_lane_azure as lane


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_IDENTITY_AZURE", raising=False)
    assert lane.nexus_live_identity_azure_enabled() is False
    assert lane.azure_skip_reason() == lane.AZURE_IDENTITY_LIVE_SETUP


def test_lane_enabled_only_for_exactly_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AZURE", "1")
    assert lane.nexus_live_identity_azure_enabled() is True
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AZURE", "0")
    assert lane.nexus_live_identity_azure_enabled() is False


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AZURE", "1")
    monkeypatch.setattr(lane, "azure_reachable", lambda: (True, ""))
    assert lane.azure_skip_reason() is None


def test_skip_reason_reports_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AZURE", "1")
    monkeypatch.setattr(lane, "azure_reachable", lambda: (False, "ClientAuthenticationError"))
    msg = lane.azure_skip_reason()
    assert msg is not None
    assert (
        "NEXUS_LIVE_IDENTITY_AZURE=1 set but Azure AD is unreachable (ClientAuthenticationError)"
        in msg
    )


def test_reachable_probe_is_secret_free(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Cred:
        def get_token(self, *_a: Any, **_k: Any) -> Any:
            raise RuntimeError("tenant=secret client_secret=leak")

    class _Resolver:
        def resolve_credential(self) -> _Cred:
            return _Cred()

    monkeypatch.setattr(lane, "AzureCredentialResolver", lambda **_: _Resolver())
    ok, reason = lane.azure_reachable()
    assert ok is False
    assert reason == "RuntimeError"  # type name only — no tenant / secret leak


def test_reachable_true_when_token_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Cred:
        def get_token(self, scope: str) -> dict[str, str]:
            assert scope == "https://graph.microsoft.com/.default"
            return {"token": "..."}

    class _Resolver:
        def resolve_credential(self) -> _Cred:
            return _Cred()

    monkeypatch.setattr(lane, "AzureCredentialResolver", lambda **_: _Resolver())
    assert lane.azure_reachable() == (True, "")
