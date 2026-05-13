"""Tests for `multi_cloud_posture.tools.azure_activity`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from multi_cloud_posture.tools.azure_activity import (
    AzureActivityReaderError,
    read_azure_activity,
)


def _record(
    *,
    record_id: str = "/subscriptions/aaa-bbb/providers/microsoft.insights/eventtypes/management/values/evt-001",
    operation_name: str = "Microsoft.Authorization/roleAssignments/write",
    category: str = "Administrative",
    level: str = "Informational",
    status: str = "Succeeded",
    caller: str = "user@example.com",
    resource_id: str = "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
    event_timestamp: str = "2026-05-13T12:00:00Z",
    operation_name_dict_form: bool = False,
) -> dict[str, Any]:
    op_name: Any = (
        {"value": operation_name, "localizedValue": operation_name}
        if operation_name_dict_form
        else operation_name
    )
    return {
        "id": record_id,
        "eventDataId": record_id.split("/")[-1],
        "operationName": op_name,
        "category": {"value": category, "localizedValue": category},
        "level": level,
        "status": {"value": status, "localizedValue": status},
        "caller": caller,
        "resourceId": resource_id,
        "eventTimestamp": event_timestamp,
        "correlationId": "corr-001",
        "callerIpAddress": "203.0.113.5",
    }


def _write(tmp_path: Path, records: list[dict[str, Any]], *, wrapped: bool = True) -> Path:
    p = tmp_path / "activity.json"
    p.write_text(json.dumps({"value": records}) if wrapped else json.dumps(records))
    return p


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_read_iam_record_happy_path(tmp_path: Path) -> None:
    path = _write(tmp_path, [_record()])

    out = await read_azure_activity(path=path)

    assert len(out) == 1
    r = out[0]
    assert r.operation_name == "Microsoft.Authorization/roleAssignments/write"
    assert r.operation_class == "iam"
    assert r.category == "Administrative"
    assert r.caller == "user@example.com"
    assert r.subscription_id == "aaa-bbb"
    assert r.resource_group == "rg1"
    assert r.status == "Succeeded"
    assert r.level == "Informational"
    assert r.detected_at == datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    assert r.unmapped["correlationId"] == "corr-001"
    assert r.unmapped["callerIpAddress"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_operation_name_dict_form_supported(tmp_path: Path) -> None:
    """Azure exports sometimes wrap operationName as `{"value": ..., "localizedValue": ...}`."""
    path = _write(tmp_path, [_record(operation_name_dict_form=True)])
    out = await read_azure_activity(path=path)
    assert len(out) == 1
    assert out[0].operation_name == "Microsoft.Authorization/roleAssignments/write"


@pytest.mark.asyncio
async def test_bare_array_format(tmp_path: Path) -> None:
    """Some Activity Log exports are a bare list rather than `{"value": [...]}`."""
    path = _write(tmp_path, [_record()], wrapped=False)
    out = await read_azure_activity(path=path)
    assert len(out) == 1


# ---------------------------- operation classification -------------------


@pytest.mark.parametrize(
    ("operation_name", "expected_class"),
    [
        ("Microsoft.Authorization/roleAssignments/write", "iam"),
        ("Microsoft.Authorization/policyAssignments/delete", "iam"),
        ("Microsoft.Network/networkSecurityGroups/write", "network"),
        ("Microsoft.Storage/storageAccounts/write", "storage"),
        ("Microsoft.Compute/virtualMachines/start/action", "compute"),
        ("Microsoft.KeyVault/vaults/secrets/write", "keyvault"),
        ("Microsoft.Resources/deployments/write", "other"),
        ("MICROSOFT.AUTHORIZATION/roleAssignments/WRITE", "iam"),  # case-insensitive
    ],
)
@pytest.mark.asyncio
async def test_operation_classification(
    tmp_path: Path, operation_name: str, expected_class: str
) -> None:
    path = _write(tmp_path, [_record(operation_name=operation_name)])
    out = await read_azure_activity(path=path)
    assert len(out) == 1
    assert out[0].operation_class == expected_class


# ---------------------------- forgiving on bad data ----------------------


@pytest.mark.asyncio
async def test_missing_id_dropped(tmp_path: Path) -> None:
    bad = _record()
    bad["id"] = ""
    bad["eventDataId"] = ""
    path = _write(tmp_path, [bad, _record()])
    out = await read_azure_activity(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_missing_operation_name_dropped(tmp_path: Path) -> None:
    bad = _record()
    bad["operationName"] = ""
    path = _write(tmp_path, [bad, _record()])
    out = await read_azure_activity(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_missing_category_dropped(tmp_path: Path) -> None:
    bad = _record()
    bad["category"] = ""
    path = _write(tmp_path, [bad, _record()])
    out = await read_azure_activity(path=path)
    assert len(out) == 1


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AzureActivityReaderError, match="not found"):
        await read_azure_activity(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(AzureActivityReaderError, match="not a file"):
        await read_azure_activity(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(AzureActivityReaderError, match="malformed"):
        await read_azure_activity(path=p)


@pytest.mark.asyncio
async def test_empty_value_array_returns_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, [])
    out = await read_azure_activity(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_subscription_id_falls_back_to_record_id(tmp_path: Path) -> None:
    """When resourceId is missing, subscription_id is extracted from the record_id path."""
    bad = _record()
    bad["resourceId"] = ""
    path = _write(tmp_path, [bad])
    out = await read_azure_activity(path=path)
    assert len(out) == 1
    assert out[0].subscription_id == "aaa-bbb"
