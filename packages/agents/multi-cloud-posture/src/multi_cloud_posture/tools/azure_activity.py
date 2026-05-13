"""`read_azure_activity` — filesystem ingest for Azure Activity Log records.

Reads an Azure Activity Log JSON export and converts each entry into a
typed `AzureActivityRecord`. Per ADR-005 the filesystem read happens on
`asyncio.to_thread`; the wrapper is `async` for TaskGroup fan-out.

**Supported input shape**: Activity Log records as exported via
`az monitor activity-log list -o json` OR fetched via
`azure-mgmt-monitor`'s `ActivityLogsOperations.list`. Top-level is
either a bare array of records or `{"value": [...]}`.

**Classification of `operationName`** (drives the normalizer's
finding-type choice in Task 7):
- IAM-shaped — anything matching `microsoft.authorization/.../write`
  or `delete` (role assignments, deny assignments, policy definitions)
- Network-shaped — `microsoft.network/...`
- Storage-shaped — `microsoft.storage/...`
- Compute-shaped — `microsoft.compute/...`
- KeyVault-shaped — `microsoft.keyvault/...`
- Other — anything else (preserved verbatim)

The `category` field on Azure Activity Log records (Administrative /
Security / ServiceHealth / Alert / Autoscale / Recommendation /
Policy) is also preserved — useful for filtering at the report
layer.

**Forgiving** on malformed entries (mirrors F.6 + Defender reader).
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class AzureActivityReaderError(RuntimeError):
    """The Azure Activity Log JSON feed could not be read."""


# Buckets the normalizer (Task 7) will use to route Activity records into
# specific CSPM-style findings.
_IAM_PREFIX = re.compile(r"^microsoft\.authorization/", re.IGNORECASE)
_NETWORK_PREFIX = re.compile(r"^microsoft\.network/", re.IGNORECASE)
_STORAGE_PREFIX = re.compile(r"^microsoft\.storage/", re.IGNORECASE)
_COMPUTE_PREFIX = re.compile(r"^microsoft\.compute/", re.IGNORECASE)
_KEYVAULT_PREFIX = re.compile(r"^microsoft\.keyvault/", re.IGNORECASE)


class AzureActivityRecord(BaseModel):
    """One Azure Activity Log record (any category)."""

    record_id: str = Field(min_length=1)  # the Activity Log entry's `id`
    operation_name: str = Field(min_length=1)
    operation_class: str = Field(pattern=r"^(iam|network|storage|compute|keyvault|other)$")
    category: str = Field(min_length=1)  # Administrative / Security / Policy / ...
    level: str = Field(default="Informational")  # Critical / Error / Warning / Informational
    status: str = ""  # Started / Succeeded / Failed
    caller: str = ""  # the principal that initiated the operation
    resource_id: str = ""  # the Azure resource ID affected
    subscription_id: str = ""
    resource_group: str = ""
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_azure_activity(*, path: Path) -> tuple[AzureActivityRecord, ...]:
    """Read an Azure Activity Log JSON export and return parsed records."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[AzureActivityRecord, ...]:
    if not path.exists():
        raise AzureActivityReaderError(f"azure activity json not found: {path}")
    if not path.is_file():
        raise AzureActivityReaderError(f"azure activity json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise AzureActivityReaderError(f"azure activity json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    out: list[AzureActivityRecord] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    if isinstance(blob, dict):
        value = blob.get("value")
        if isinstance(value, list):
            return [r for r in value if isinstance(r, dict)]
        return []
    if isinstance(blob, list):
        return [r for r in blob if isinstance(r, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> AzureActivityRecord | None:
    record_id = str(raw.get("id") or raw.get("eventDataId") or "")
    if not record_id:
        return None

    operation_name = _resolve_operation_name(raw)
    if not operation_name:
        return None
    operation_class = _classify_operation(operation_name)

    category = _resolve_category(raw)
    if not category:
        return None

    detected_at = _resolve_detected_at(raw)
    resource_id = str(raw.get("resourceId") or "")
    subscription_id = _resolve_subscription_id(resource_id or record_id)
    resource_group = _resolve_resource_group(resource_id)

    try:
        return AzureActivityRecord(
            record_id=record_id,
            operation_name=operation_name,
            operation_class=operation_class,
            category=category,
            level=str(raw.get("level") or "Informational"),
            status=_resolve_status(raw),
            caller=_resolve_caller(raw),
            resource_id=resource_id,
            subscription_id=subscription_id,
            resource_group=resource_group,
            detected_at=detected_at,
            unmapped=_collect_unmapped(raw),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _resolve_operation_name(raw: dict[str, Any]) -> str:
    """Activity Log records carry `operationName` as either a string or `{"value": ...}`."""
    value = raw.get("operationName")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("value") or value.get("localizedValue")
        if isinstance(inner, str):
            return inner
    return ""


def _classify_operation(operation_name: str) -> str:
    if _IAM_PREFIX.match(operation_name):
        return "iam"
    if _NETWORK_PREFIX.match(operation_name):
        return "network"
    if _STORAGE_PREFIX.match(operation_name):
        return "storage"
    if _COMPUTE_PREFIX.match(operation_name):
        return "compute"
    if _KEYVAULT_PREFIX.match(operation_name):
        return "keyvault"
    return "other"


def _resolve_category(raw: dict[str, Any]) -> str:
    value = raw.get("category")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("value") or value.get("localizedValue")
        if isinstance(inner, str):
            return inner
    return ""


def _resolve_status(raw: dict[str, Any]) -> str:
    value = raw.get("status")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("value") or value.get("localizedValue")
        if isinstance(inner, str):
            return inner
    return ""


def _resolve_caller(raw: dict[str, Any]) -> str:
    """Activity Log `caller` is typically a UPN or service-principal-object-id."""
    return str(raw.get("caller") or raw.get("callerIpAddress") or "")


def _resolve_detected_at(raw: dict[str, Any]) -> datetime:
    for key in ("eventTimestamp", "submissionTimestamp", "timestamp"):
        value = raw.get(key)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
    return datetime.now(UTC)


def _resolve_subscription_id(some_id: str) -> str:
    parts = some_id.split("/")
    if len(parts) > 2 and parts[1].lower() == "subscriptions":
        return parts[2]
    return ""


def _resolve_resource_group(resource_id: str) -> str:
    """`/subscriptions/x/resourceGroups/<rg>/providers/...` → `<rg>`."""
    parts = resource_id.split("/")
    if len(parts) > 4 and parts[3].lower() == "resourcegroups":
        return parts[4]
    return ""


def _collect_unmapped(raw: dict[str, Any]) -> dict[str, Any]:
    """Preserve Activity-Log fields not in the typed shape (correlation IDs, properties, etc.)."""
    out: dict[str, Any] = {}
    for key in (
        "correlationId",
        "operationId",
        "callerIpAddress",
        "claims",
        "httpRequest",
        "properties",
        "authorization",
        "tenantId",
    ):
        if key in raw:
            out[key] = raw[key]
    return out


__all__ = [
    "AzureActivityReaderError",
    "AzureActivityRecord",
    "read_azure_activity",
]
