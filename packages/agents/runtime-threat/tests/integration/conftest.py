"""Integration fixtures (D.3 v0.2 Task 18) — the NEXUS_LIVE_RUNTIME_* gates."""

from __future__ import annotations

import pytest
from runtime_threat.live_lane import (
    runtime_falco_live_skip_reason,
    runtime_tracee_live_skip_reason,
)


@pytest.fixture
def falco_gate() -> None:
    """Skip unless NEXUS_LIVE_RUNTIME_FALCO=1 AND the Falco gRPC socket is reachable."""
    reason = runtime_falco_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)


@pytest.fixture
def tracee_gate() -> None:
    """Skip unless NEXUS_LIVE_RUNTIME_TRACEE=1 AND the Tracee pipe is reachable."""
    reason = runtime_tracee_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
