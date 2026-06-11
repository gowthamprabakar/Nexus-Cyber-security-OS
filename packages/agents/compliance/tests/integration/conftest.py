"""Integration fixtures (compliance v0.2 Task 19) — the NEXUS_LIVE_COMPLIANCE gate."""

from __future__ import annotations

import pytest
from compliance.live_lane import compliance_live_skip_reason


@pytest.fixture
def compliance_gate() -> None:
    reason = compliance_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
