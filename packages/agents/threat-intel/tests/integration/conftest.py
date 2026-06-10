"""Integration fixtures (D.8 v0.2 Task 17) — the NEXUS_LIVE_THREAT_INTEL gate."""

from __future__ import annotations

import pytest
from threat_intel.live_lane import threat_intel_live_skip_reason


@pytest.fixture
def live_gate() -> None:
    """Skip the test unless NEXUS_LIVE_THREAT_INTEL=1 AND all feeds are reachable."""
    reason = threat_intel_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
