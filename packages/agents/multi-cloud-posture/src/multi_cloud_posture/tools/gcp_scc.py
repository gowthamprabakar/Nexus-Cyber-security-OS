"""`read_gcp_findings` — filesystem ingest for GCP Security Command Center findings.

Reads a GCP Security Command Center (SCC) findings JSON export and
converts each entry into a typed `GcpSccFinding`. Per ADR-005 the
filesystem read happens on `asyncio.to_thread`; the wrapper is `async`
for TaskGroup fan-out.

**Supported input shapes** (auto-detected from the top-level JSON):

1. **`findings` snapshot** — the canonical SCC `ListFindingsResponse`
   shape: `{"listFindingsResults": [{"finding": {...}, "resource":
   {...}}, ...]}`.
2. **Bare findings array** — `[{...finding...}, {...}]` where each
   element is a flat finding dict (older SCC API variant).
3. **Wrapped findings** — `{"findings": [...]}` (some `gcloud scc
   findings list --format=json` exports).

Phase 1c live mode swaps the implementation behind this same signature
to `google-cloud-securitycenter`'s `SecurityCenterClient.list_findings`
pager.

**Forgiving** on malformed entries — a single bad object is dropped,
not the whole file. Mirrors F.6 + Suricata + DNS + Defender readers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class GcpSccReaderError(RuntimeError):
    """The GCP SCC JSON feed could not be read."""


class GcpSccFinding(BaseModel):
    """One GCP Security Command Center finding."""

    finding_name: str = Field(min_length=1)
    # SCC finding paths: organizations/<n>/sources/<sid>/findings/<fid>
    parent: str = Field(min_length=1)  # `organizations/<n>/sources/<sid>`
    resource_name: str = Field(min_length=1)
    category: str = Field(min_length=1)  # MALWARE / OPEN_FIREWALL / PUBLIC_BUCKET / ...
    state: str = Field(default="ACTIVE")  # ACTIVE / INACTIVE
    severity: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|SEVERITY_UNSPECIFIED)$")
    description: str = ""
    external_uri: str = ""
    project_id: str = ""
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_gcp_findings(*, path: Path) -> tuple[GcpSccFinding, ...]:
    """Read a GCP SCC findings JSON export and return parsed findings."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[GcpSccFinding, ...]:
    if not path.exists():
        raise GcpSccReaderError(f"gcp scc json not found: {path}")
    if not path.is_file():
        raise GcpSccReaderError(f"gcp scc json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise GcpSccReaderError(f"gcp scc json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    out: list[GcpSccFinding] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    """Pull a list of {finding, resource?} dicts out of the top-level JSON.

    Each returned element has shape `{"finding": {...}, "resource": {...?}}`
    so the parser can pull resource data uniformly across all three input
    shapes.
    """
    if isinstance(blob, list):
        # Bare findings array — each element is a flat finding dict.
        return [{"finding": r} for r in blob if isinstance(r, dict)]
    if not isinstance(blob, dict):
        return []
    # Canonical ListFindingsResponse.
    results = blob.get("listFindingsResults")
    if isinstance(results, list):
        out: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, dict) and isinstance(r.get("finding"), dict):
                out.append(r)
        return out
    # `gcloud` flat-list wrapper.
    findings = blob.get("findings")
    if isinstance(findings, list):
        return [{"finding": r} for r in findings if isinstance(r, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> GcpSccFinding | None:
    finding = raw.get("finding")
    if not isinstance(finding, dict):
        return None
    name = str(finding.get("name") or "")
    if not name:
        return None
    parent = str(finding.get("parent") or _derive_parent(name))
    if not parent:
        return None
    resource_name = str(
        finding.get("resourceName") or (raw.get("resource") or {}).get("name") or ""
    )
    if not resource_name:
        return None
    category = str(finding.get("category") or "")
    if not category:
        return None
    severity = _resolve_severity(finding.get("severity"))
    if severity is None:
        return None

    detected_at = _resolve_detected_at(finding)
    project_id = _resolve_project_id(resource_name)
    resource_blob = raw.get("resource")
    resource_dict: dict[str, Any] = resource_blob if isinstance(resource_blob, dict) else {}

    try:
        return GcpSccFinding(
            finding_name=name,
            parent=parent,
            resource_name=resource_name,
            category=category,
            state=str(finding.get("state") or "ACTIVE"),
            severity=severity,
            description=str(finding.get("description") or ""),
            external_uri=str(finding.get("externalUri") or ""),
            project_id=project_id,
            detected_at=detected_at,
            unmapped=_collect_unmapped(finding, resource_dict),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _derive_parent(finding_name: str) -> str:
    """`organizations/<n>/sources/<sid>/findings/<fid>` → `organizations/<n>/sources/<sid>`."""
    parts = finding_name.split("/findings/")
    return parts[0] if parts else ""


def _resolve_severity(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    upper = value.upper()
    if upper not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"}:
        return None
    return upper


def _resolve_detected_at(finding: dict[str, Any]) -> datetime:
    for key in ("eventTime", "createTime"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
    return datetime.now(UTC)


def _resolve_project_id(resource_name: str) -> str:
    """`//compute.googleapis.com/projects/<id>/...` → `<id>`.

    Also handles `projects/<id>/...` and `//cloudresourcemanager.googleapis.com/projects/<id>`.
    """
    parts = resource_name.split("/projects/")
    if len(parts) >= 2:
        tail = parts[1]
        sep = tail.find("/")
        if sep == -1:
            return tail
        return tail[:sep]
    return ""


def _collect_unmapped(finding: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting SCC fields not in the typed shape."""
    out: dict[str, Any] = {}
    for key in (
        "sourceProperties",
        "indicator",
        "vulnerability",
        "compliances",
        "mitreAttack",
        "iamBindings",
        "nextSteps",
    ):
        if key in finding:
            out[key] = finding[key]
    if resource:
        out["resource"] = resource
    return out


__all__ = [
    "GcpSccFinding",
    "GcpSccReaderError",
    "read_gcp_findings",
]
