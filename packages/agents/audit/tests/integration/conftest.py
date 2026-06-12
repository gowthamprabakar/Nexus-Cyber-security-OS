"""Integration fixtures (audit v0.2 Task 16) — the NEXUS_LIVE_AUDIT gate."""

from __future__ import annotations

import pytest
from audit.live_lane import audit_live_skip_reason


@pytest.fixture
def audit_gate() -> None:
    reason = audit_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
