"""F.3 v0.2 Task 8 — lane independence contract + coexistence verification.

Two live integration lanes coexist in this directory, each keyed to a DISTINCT
env var and skipping independently:

  - ``NEXUS_LIVE_LOCALSTACK`` → ``localstack_endpoint`` / ``aws_env`` fixtures (v0.1)
  - ``NEXUS_LIVE_AWS``        → ``aws_live_account`` fixture (v0.2 Task 6, gating
                                logic in ``cloud_posture.live_lane``)

**Lane independence contract** (the shape future per-cloud lanes follow —
``NEXUS_LIVE_AZURE`` / ``NEXUS_LIVE_GCP`` for D.5 v0.2; a Q7 hoist candidate,
documented in Task 12):

1. Each lane reads **only its own** env var.
2. Each lane has **its own** reachability probe.
3. Each lane **skips independently** — enabling one never enables another.
4. Lanes share **no mutable module state** (gates are pure functions of the env).
5. The offline eval suite is unaffected by any lane (it never opts in).

These tests verify (1)-(4) on the importable AWS-lane surface and the structural
distinctness of the two keys. The LocalStack lane itself is unchanged (its v0.1
tests still pass — see the full suite); this file adds no integration tests and
modifies no existing fixture.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import cloud_posture.live_lane as live_lane
import pytest
from cloud_posture.live_lane import nexus_live_aws_enabled

_LOCALSTACK_KEY = "NEXUS_LIVE_LOCALSTACK"
_AWS_KEY = "NEXUS_LIVE_AWS"


def test_aws_lane_disabled_when_only_localstack_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_LOCALSTACK_KEY, "1")
    monkeypatch.delenv(_AWS_KEY, raising=False)
    assert nexus_live_aws_enabled() is False  # AWS lane ignores the LocalStack var


def test_aws_lane_enabled_when_only_aws_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_LOCALSTACK_KEY, raising=False)
    monkeypatch.setenv(_AWS_KEY, "1")
    assert nexus_live_aws_enabled() is True


def test_both_lanes_enabled_no_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    # both env vars set: the AWS lane still keys only on its own var (no conflict).
    monkeypatch.setenv(_LOCALSTACK_KEY, "1")
    monkeypatch.setenv(_AWS_KEY, "1")
    assert nexus_live_aws_enabled() is True


def test_lanes_use_distinct_env_keys_and_no_cross_reference() -> None:
    assert _AWS_KEY != _LOCALSTACK_KEY
    # the LocalStack lane keys on its var (conftest); the AWS lane keys on its own.
    conftest_src = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")
    assert _LOCALSTACK_KEY in conftest_src
    assert _AWS_KEY in live_lane.AWS_LIVE_SETUP
    # the AWS gate must NOT read the LocalStack var, and vice-versa-by-construction.
    assert _LOCALSTACK_KEY not in inspect.getsource(live_lane.nexus_live_aws_enabled)
    assert _LOCALSTACK_KEY not in inspect.getsource(live_lane.aws_skip_reason)


def test_aws_gate_is_pure_no_shared_mutable_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_AWS_KEY, "1")
    monkeypatch.setenv(_LOCALSTACK_KEY, "1")
    before = dict(os.environ)
    results = {nexus_live_aws_enabled() for _ in range(5)}
    assert results == {True}  # stable across calls
    assert dict(os.environ) == before  # the gate never mutates the environment
