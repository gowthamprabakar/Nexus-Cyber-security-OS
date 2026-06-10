"""Integration fixtures for identity's live eval lanes (D.2 v0.2 Task 18, WI-I4)."""

from __future__ import annotations

import pytest
from identity.live_lane_aws import aws_skip_reason as _aws_skip_reason
from identity.live_lane_azure import azure_skip_reason as _azure_skip_reason


@pytest.fixture
def aws_identity_live() -> None:
    """Skip unless `NEXUS_LIVE_IDENTITY_AWS=1` and live AWS is reachable."""
    reason = _aws_skip_reason()
    if reason is not None:
        pytest.skip(reason)


@pytest.fixture
def azure_identity_live() -> None:
    """Skip unless `NEXUS_LIVE_IDENTITY_AZURE=1` and live Azure is reachable."""
    reason = _azure_skip_reason()
    if reason is not None:
        pytest.skip(reason)
