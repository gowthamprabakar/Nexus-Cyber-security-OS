"""`read_azure_findings` — filesystem ingest for Azure Defender for Cloud findings.

Reads an Azure Defender for Cloud "assessments" or "alerts" JSON export
and converts each entry into a typed `AzureDefenderFinding`. Per ADR-005
the filesystem read happens on `asyncio.to_thread`; the wrapper is
`async` for TaskGroup fan-out.

**Supported input shapes** (auto-detected from the top-level JSON):

1. **`assessments` snapshot** — the canonical Defender for Cloud
   security-recommendations response. Top-level key `value` carries
   a list of objects with `id`, `name`, `type=Microsoft.Security/
   assessments`, `properties.status.code`, `properties.severity`,
   `properties.resourceDetails`, etc.
2. **`alerts` snapshot** — Defender alerts (active threats). Top-level
   key `value` carries objects with `properties.alertDisplayName`,
   `properties.severity`, `properties.resourceIdentifiers`, etc.
3. **Plain array** — a list at the top level. Each element treated as
   either shape; we pick the one whose `properties` keys match.

Phase 1c live mode swaps the implementation behind this same signature
to `azure-mgmt-security`'s `AssessmentsOperations.list` / `AlertsOperations.
list_by_subscription` pagers.

**Forgiving** on malformed entries — a single bad object is dropped,
not the whole file. Mirrors F.6 + Suricata + DNS + VPC readers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class AzureDefenderReaderError(RuntimeError):
    """The Azure Defender JSON feed could not be read."""


class AzureDefenderKind(BaseModel):
    """Sentinel — the `kind` of Defender record this object represents."""

    kind: str  # "assessment" or "alert"


class AzureDefenderFinding(BaseModel):
    """One Azure Defender for Cloud record (assessment or alert).

    Both Defender response shapes collapse to this typed model so the
    normalizer (Task 7) doesn't have to branch on per-shape keys.
    """

    kind: str = Field(pattern=r"^(assessment|alert)$")
    record_id: str = Field(min_length=1)  # the Azure resource ID of the record itself
    display_name: str = Field(min_length=1)  # human-readable title
    severity: str = Field(pattern=r"^(Low|Medium|High|Critical|Informational)$")
    status: str = Field(default="Unhealthy")  # assessments: Healthy/Unhealthy/NotApplicable
    description: str = ""
    resource_id: str = ""  # the Azure resource ID being assessed
    subscription_id: str = ""
    assessment_type: str = ""  # CustomerManaged / BuiltIn (assessments only)
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_azure_findings(*, path: Path) -> tuple[AzureDefenderFinding, ...]:
    """Read an Azure Defender JSON export and return the parsed findings."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[AzureDefenderFinding, ...]:
    if not path.exists():
        raise AzureDefenderReaderError(f"azure defender json not found: {path}")
    if not path.is_file():
        raise AzureDefenderReaderError(f"azure defender json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise AzureDefenderReaderError(f"azure defender json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    out: list[AzureDefenderFinding] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    """Pull a list of record dicts out of the top-level JSON.

    Supports {"value": [...]} (canonical Azure response) or a bare list.
    """
    if isinstance(blob, dict):
        value = blob.get("value")
        if isinstance(value, list):
            return [r for r in value if isinstance(r, dict)]
        return []
    if isinstance(blob, list):
        return [r for r in blob if isinstance(r, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> AzureDefenderFinding | None:
    record_id = str(raw.get("id", ""))
    if not record_id:
        return None
    record_type = str(raw.get("type", ""))
    kind = _classify_kind(record_type, raw)
    if kind is None:
        return None
    props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    if not isinstance(props, dict):
        return None

    display_name = _resolve_display_name(kind, props, fallback=str(raw.get("name", "")))
    if not display_name:
        return None
    severity = _resolve_severity(props)
    if severity is None:
        return None

    detected_at = _resolve_detected_at(kind, props)
    resource_id = _resolve_resource_id(kind, props)
    subscription_id = _resolve_subscription_id(record_id)

    try:
        return AzureDefenderFinding(
            kind=kind,
            record_id=record_id,
            display_name=display_name,
            severity=severity,
            status=str((props.get("status") or {}).get("code", "")) or "Unhealthy",
            description=str(props.get("description", "")),
            resource_id=resource_id,
            subscription_id=subscription_id,
            assessment_type=str((props.get("metadata") or {}).get("assessmentType") or ""),
            detected_at=detected_at,
            unmapped=_collect_unmapped(props),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _classify_kind(record_type: str, raw: dict[str, Any]) -> str | None:
    """Determine whether a Defender record is an assessment or an alert."""
    low = record_type.lower()
    if "assessment" in low:
        return "assessment"
    if "alert" in low:
        return "alert"
    # Heuristic on property keys when `type` is absent / unrecognised.
    props = raw.get("properties") or {}
    if not isinstance(props, dict):
        return None
    if "alertDisplayName" in props or "alertType" in props:
        return "alert"
    if "displayName" in props or "status" in props:
        return "assessment"
    return None


def _resolve_display_name(kind: str, props: dict[str, Any], *, fallback: str) -> str:
    if kind == "alert":
        return str(props.get("alertDisplayName") or props.get("displayName") or fallback)
    return str(props.get("displayName") or fallback)


def _resolve_severity(props: dict[str, Any]) -> str | None:
    """Pull the severity string from one of two possible keys; normalise capitalisation."""
    raw = props.get("severity")
    if not isinstance(raw, str) or not raw:
        return None
    normalised = raw[0].upper() + raw[1:].lower()
    if normalised not in {"Low", "Medium", "High", "Critical", "Informational"}:
        return None
    return normalised


def _resolve_detected_at(kind: str, props: dict[str, Any]) -> datetime:
    keys: tuple[str, ...]
    if kind == "assessment":
        keys = ("timeGeneratedUtc", "lastEvaluationTimeUtc")
    else:
        keys = ("timeGeneratedUtc", "startTimeUtc", "lastDetectedTimeUtc")
    for key in keys:
        value = props.get(key)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
    return datetime.now(UTC)


def _resolve_resource_id(kind: str, props: dict[str, Any]) -> str:
    if kind == "alert":
        identifiers = props.get("resourceIdentifiers")
        if isinstance(identifiers, list) and identifiers:
            first = identifiers[0]
            if isinstance(first, dict):
                return str(first.get("azureResourceId") or "")
    rd = props.get("resourceDetails")
    if isinstance(rd, dict):
        return str(rd.get("Id") or rd.get("id") or "")
    return ""


def _resolve_subscription_id(record_id: str) -> str:
    """Pull `<sub-id>` out of `/subscriptions/<sub-id>/...`."""
    parts = record_id.split("/")
    if len(parts) > 2 and parts[1].lower() == "subscriptions":
        return parts[2]
    return ""


def _collect_unmapped(props: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting Defender fields not in the typed shape."""
    out: dict[str, Any] = {}
    for key in (
        "alertType",
        "compromisedEntity",
        "category",
        "additionalData",
        "links",
        "remediation",
        "remediationSteps",
    ):
        if key in props:
            out[key] = props[key]
    return out


__all__ = [
    "AzureDefenderFinding",
    "AzureDefenderReaderError",
    "read_azure_findings",
]
