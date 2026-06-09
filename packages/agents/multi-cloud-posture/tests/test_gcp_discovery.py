"""D.5 v0.2 Task 7 — GCP project + region discovery tests (no live GCP)."""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from multi_cloud_posture.credentials_gcp import GcpCredentialResolver
from multi_cloud_posture.tools import gcp_discovery
from multi_cloud_posture.tools.gcp_discovery import (
    GcpDiscoveryError,
    discover_project_id,
    discover_regions,
)


@pytest.mark.asyncio
async def test_project_from_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "env-proj")
    r = GcpCredentialResolver()
    with patch.object(GcpCredentialResolver, "resolve_credential") as resolve:
        assert await discover_project_id(r) == "env-proj"
    resolve.assert_not_called()  # env short-circuits credential resolution


@pytest.mark.asyncio
async def test_project_from_gcp_project_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "alt-proj")
    r = GcpCredentialResolver()
    assert await discover_project_id(r) == "alt-proj"


@pytest.mark.asyncio
async def test_project_from_adc_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    r = GcpCredentialResolver()
    with patch.object(
        GcpCredentialResolver, "resolve_credential", return_value=(MagicMock(), "adc-proj")
    ):
        assert await discover_project_id(r) == "adc-proj"


@pytest.mark.asyncio
async def test_project_raises_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    r = GcpCredentialResolver()
    with (
        patch.object(GcpCredentialResolver, "resolve_credential", return_value=(MagicMock(), None)),
        pytest.raises(GcpDiscoveryError, match="no GCP project"),
    ):
        await discover_project_id(r)


@pytest.mark.asyncio
async def test_regions_sorted_and_filtered() -> None:
    client = MagicMock()
    client.list.return_value = [
        SimpleNamespace(name="us-west1"),
        SimpleNamespace(name="europe-west1"),
        SimpleNamespace(name=None),
        SimpleNamespace(name="us-central1"),
    ]
    r = GcpCredentialResolver()
    with patch.object(GcpCredentialResolver, "client", return_value=client):
        assert await discover_regions(r, "proj-1") == [
            "europe-west1",
            "us-central1",
            "us-west1",
        ]


@pytest.mark.asyncio
async def test_regions_passes_project() -> None:
    client = MagicMock()
    client.list.return_value = []
    r = GcpCredentialResolver()
    with patch.object(GcpCredentialResolver, "client", return_value=client):
        await discover_regions(r, "proj-XYZ")
    client.list.assert_called_once_with(project="proj-XYZ")


def test_q6_no_org_or_project_listing_apis() -> None:
    """Q6 structural guard: discovery references no organization / folder /
    projects-listing API."""
    src = inspect.getsource(gcp_discovery)
    for forbidden in (
        "organizations",
        "list_projects",
        "ProjectsClient",
        "FoldersClient",
        "search_projects",
    ):
        assert forbidden not in src
