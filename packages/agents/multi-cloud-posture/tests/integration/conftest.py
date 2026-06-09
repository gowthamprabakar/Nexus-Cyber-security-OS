"""Fixtures for D.5 live integration tests (Azure + GCP lanes).

Two DISTINCT, independent gates (mirrors F.3's lane-independence contract):

- ``NEXUS_LIVE_AZURE=1`` → ``azure_live_subscription`` (Task 13)
- ``NEXUS_LIVE_GCP=1``   → ``gcp_live_project`` (Task 14)

Each skips (with copy-paste setup) unless its env is set AND the cloud is
reachable, so a normal ``pytest`` / CI run never touches a cloud.
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.fixture(scope="session")
def azure_live_subscription() -> str:
    """Current Azure subscription id for the live lane. Skips when
    ``NEXUS_LIVE_AZURE`` is unset or Azure is unreachable (Task 13)."""
    from multi_cloud_posture.credentials_azure import AzureCredentialResolver
    from multi_cloud_posture.live_lane_azure import azure_skip_reason
    from multi_cloud_posture.tools.azure_discovery import discover_subscription_id

    reason = azure_skip_reason()
    if reason is not None:
        pytest.skip(reason)
    return asyncio.run(discover_subscription_id(AzureCredentialResolver()))


@pytest.fixture(scope="session")
def gcp_live_project() -> str:
    """Current GCP project id for the live lane. Skips when ``NEXUS_LIVE_GCP`` is
    unset or GCP is unreachable (Task 14). Independent of the Azure lane."""
    from multi_cloud_posture.credentials_gcp import GcpCredentialResolver
    from multi_cloud_posture.live_lane_gcp import gcp_skip_reason
    from multi_cloud_posture.tools.gcp_discovery import discover_project_id

    reason = gcp_skip_reason()
    if reason is not None:
        pytest.skip(reason)
    return asyncio.run(discover_project_id(GcpCredentialResolver()))
