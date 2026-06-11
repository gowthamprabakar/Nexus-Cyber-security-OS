"""Integration fixtures (data-security v0.2 Task 20) — the NEXUS_LIVE_DATA_SECURITY gate."""

from __future__ import annotations

import pytest
from data_security.live_lane import data_security_live_skip_reason


@pytest.fixture
def data_security_gate() -> None:
    reason = data_security_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
