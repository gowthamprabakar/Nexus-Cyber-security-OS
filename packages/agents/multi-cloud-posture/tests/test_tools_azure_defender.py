"""Tests for `multi_cloud_posture.tools.azure_defender`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from multi_cloud_posture.tools.azure_defender import (
    AzureDefenderReaderError,
    read_azure_findings,
)


def _assessment(
    *,
    record_id: str = "/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/asmt-1",
    display_name: str = "Allow only known IPs to connect to storage",
    severity: str = "High",
    status: str = "Unhealthy",
    resource_id: str = "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
    time_generated_utc: str = "2026-05-13T12:00:00Z",
) -> dict[str, Any]:
    return {
        "id": record_id,
        "name": record_id.split("/")[-1],
        "type": "Microsoft.Security/assessments",
        "properties": {
            "displayName": display_name,
            "severity": severity,
            "status": {"code": status},
            "description": "Storage account allows public access; restrict to known IPs.",
            "resourceDetails": {"Id": resource_id, "Source": "Azure"},
            "timeGeneratedUtc": time_generated_utc,
            "metadata": {"assessmentType": "BuiltIn"},
            "remediationSteps": ["1. Restrict NSG rules.", "2. Update storage firewall."],
        },
    }


def _alert(
    *,
    record_id: str = "/subscriptions/aaa-bbb/providers/Microsoft.Security/alerts/alert-1",
    display_name: str = "Suspicious sign-in to subscription",
    severity: str = "Medium",
    resource_id: str = "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
    start_time_utc: str = "2026-05-13T12:00:00Z",
) -> dict[str, Any]:
    return {
        "id": record_id,
        "name": record_id.split("/")[-1],
        "type": "Microsoft.Security/alerts",
        "properties": {
            "alertDisplayName": display_name,
            "severity": severity,
            "description": "Sign-in from an unusual IP range.",
            "resourceIdentifiers": [{"azureResourceId": resource_id, "type": "AzureResource"}],
            "startTimeUtc": start_time_utc,
            "alertType": "SuspiciousIPAccess",
            "compromisedEntity": "vm1",
        },
    }


def _write_value_wrapped(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    p = tmp_path / "defender.json"
    p.write_text(json.dumps({"value": records}))
    return p


def _write_array(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    p = tmp_path / "defender.json"
    p.write_text(json.dumps(records))
    return p


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_read_assessment_happy_path(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [_assessment()])

    out = await read_azure_findings(path=path)

    assert len(out) == 1
    f = out[0]
    assert f.kind == "assessment"
    assert f.severity == "High"
    assert f.status == "Unhealthy"
    assert f.display_name == "Allow only known IPs to connect to storage"
    assert f.subscription_id == "aaa-bbb"
    assert f.assessment_type == "BuiltIn"
    assert f.resource_id.endswith("/storageAccounts/sa1")
    assert f.detected_at == datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    assert f.unmapped["remediationSteps"][0].startswith("1. Restrict")


@pytest.mark.asyncio
async def test_read_alert_happy_path(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [_alert()])

    out = await read_azure_findings(path=path)
    assert len(out) == 1
    f = out[0]
    assert f.kind == "alert"
    assert f.severity == "Medium"
    assert f.display_name == "Suspicious sign-in to subscription"
    assert f.resource_id.endswith("/virtualMachines/vm1")
    assert f.unmapped["alertType"] == "SuspiciousIPAccess"
    assert f.unmapped["compromisedEntity"] == "vm1"


@pytest.mark.asyncio
async def test_read_mixed_assessment_and_alert(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [_assessment(), _alert()])

    out = await read_azure_findings(path=path)
    kinds = sorted(f.kind for f in out)
    assert kinds == ["alert", "assessment"]


@pytest.mark.asyncio
async def test_read_bare_array_format(tmp_path: Path) -> None:
    """Some Azure exports return a bare list rather than `{"value": [...]}`."""
    path = _write_array(tmp_path, [_assessment()])

    out = await read_azure_findings(path=path)
    assert len(out) == 1


# ---------------------------- severity normalisation ---------------------


@pytest.mark.asyncio
async def test_severity_lowercase_normalised(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [_assessment(severity="high")])
    out = await read_azure_findings(path=path)
    assert out[0].severity == "High"


@pytest.mark.asyncio
async def test_severity_unknown_dropped(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [_assessment(severity="Catastrophic")])
    out = await read_azure_findings(path=path)
    assert out == ()


# ---------------------------- forgiving on bad data ----------------------


@pytest.mark.asyncio
async def test_missing_id_dropped(tmp_path: Path) -> None:
    bad = _assessment()
    bad["id"] = ""
    path = _write_value_wrapped(tmp_path, [bad, _assessment()])
    out = await read_azure_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_missing_properties_dropped(tmp_path: Path) -> None:
    bad = {"id": "/x/y", "type": "Microsoft.Security/assessments"}
    path = _write_value_wrapped(tmp_path, [bad, _assessment()])
    out = await read_azure_findings(path=path)
    assert len(out) == 1
    assert out[0].kind == "assessment"


@pytest.mark.asyncio
async def test_unknown_type_classified_by_heuristic(tmp_path: Path) -> None:
    """Property-key heuristic catches records with non-canonical `type` fields."""
    record = _alert()
    record["type"] = "Microsoft.Security/something-else"
    path = _write_value_wrapped(tmp_path, [record])
    out = await read_azure_findings(path=path)
    assert len(out) == 1
    assert out[0].kind == "alert"  # alertDisplayName triggers the heuristic


@pytest.mark.asyncio
async def test_unclassifiable_record_dropped(tmp_path: Path) -> None:
    bad = {"id": "/x/y", "type": "Microsoft.Compute/virtualMachines", "properties": {}}
    path = _write_value_wrapped(tmp_path, [bad])
    out = await read_azure_findings(path=path)
    assert out == ()


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AzureDefenderReaderError, match="not found"):
        await read_azure_findings(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(AzureDefenderReaderError, match="not a file"):
        await read_azure_findings(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(AzureDefenderReaderError, match="malformed"):
        await read_azure_findings(path=p)


@pytest.mark.asyncio
async def test_empty_value_array_returns_empty(tmp_path: Path) -> None:
    path = _write_value_wrapped(tmp_path, [])
    out = await read_azure_findings(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_non_dict_top_level_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "scalar.json"
    p.write_text("123")
    out = await read_azure_findings(path=p)
    assert out == ()
