"""Integration fixtures (D.6 v0.2 Task 18) — the NEXUS_LIVE_K8S_POSTURE gate."""

from __future__ import annotations

import pytest
from k8s_posture.live_lane import k8s_posture_live_skip_reason


@pytest.fixture
def k8s_gate() -> None:
    reason = k8s_posture_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
