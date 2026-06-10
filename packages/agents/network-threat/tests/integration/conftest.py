"""Integration fixtures (D.4 v0.2 Task 19) — the NEXUS_LIVE_NETWORK_* gates."""

from __future__ import annotations

import pytest
from network_threat.live_lane import (
    network_suricata_live_skip_reason,
    network_vpc_aws_live_skip_reason,
    network_zeek_live_skip_reason,
)


@pytest.fixture
def suricata_gate() -> None:
    reason = network_suricata_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)


@pytest.fixture
def zeek_gate() -> None:
    reason = network_zeek_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)


@pytest.fixture
def vpc_gate() -> None:
    reason = network_vpc_aws_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
