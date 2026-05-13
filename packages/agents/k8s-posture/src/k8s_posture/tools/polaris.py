"""`read_polaris` — filesystem ingest for Polaris JSON output.

Reads a Polaris (`polaris audit --format=json`) export and converts
each failing per-container check into a typed `PolarisFinding`. Per
ADR-005 the filesystem read happens on `asyncio.to_thread`; the
wrapper is `async` for TaskGroup fan-out.

**Polaris JSON shape** (canonical):

```json
{
  "PolarisOutputVersion": "1.0",
  "Results": [
    {
      "Name": "frontend",
      "Namespace": "production",
      "Kind": "Deployment",
      "Results": { "<workload-check-id>": {...} },
      "PodResult": {
        "Name": "frontend-7f9d8c4b6-x2k5p",
        "Results": { "<pod-check-id>": {...} },
        "ContainerResults": [
          {
            "Name": "nginx",
            "Results": {
              "runAsRootAllowed": {
                "ID": "runAsRootAllowed",
                "Message": "Should not be allowed to run as root",
                "Success": false,
                "Severity": "danger",
                "Category": "Security"
              }
            }
          }
        ]
      }
    }
  ]
}
```

The walker visits **three check levels**:

1. Workload-level: `Results[].Results.<check>`
2. Pod-level: `Results[].PodResult.Results.<check>`
3. Container-level: `Results[].PodResult.ContainerResults[].Results.<check>`

Only checks with `Success: false` become findings (matching the Polaris
"the check failed" semantics). The reader is **forgiving** — bad
records are dropped, not the whole file. Top-level malformed JSON
raises `PolarisReaderError` explicitly.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class PolarisReaderError(RuntimeError):
    """The Polaris JSON feed could not be read."""


class PolarisFinding(BaseModel):
    """One failing Polaris check (workload / pod / container level)."""

    check_id: str = Field(min_length=1)  # e.g. "runAsRootAllowed"
    message: str = Field(min_length=1)
    severity: str = Field(pattern=r"^(danger|warning)$")
    category: str = Field(default="")
    workload_kind: str = Field(min_length=1)  # Deployment / Pod / StatefulSet / ...
    workload_name: str = Field(min_length=1)
    namespace: str = Field(default="default")
    container_name: str = Field(default="")  # empty for workload/pod-level checks
    check_level: str = Field(pattern=r"^(workload|pod|container)$")
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_polaris(*, path: Path) -> tuple[PolarisFinding, ...]:
    """Read a Polaris JSON file and return failing checks as findings."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[PolarisFinding, ...]:
    if not path.exists():
        raise PolarisReaderError(f"polaris json not found: {path}")
    if not path.is_file():
        raise PolarisReaderError(f"polaris json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise PolarisReaderError(f"polaris json is malformed: {exc}") from exc

    results = _extract_results(blob)
    detected_at = datetime.now(UTC)
    out: list[PolarisFinding] = []
    for workload in results:
        for finding in _walk_workload(workload, detected_at=detected_at):
            out.append(finding)
    return tuple(out)


def _extract_results(blob: Any) -> list[dict[str, Any]]:
    """Pull the `Results` array out of the top-level JSON (or accept a bare array)."""
    if isinstance(blob, dict):
        results = blob.get("Results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return []
    if isinstance(blob, list):
        return [r for r in blob if isinstance(r, dict)]
    return []


def _walk_workload(
    workload: dict[str, Any],
    *,
    detected_at: datetime,
) -> list[PolarisFinding]:
    """Walk one Results[] entry across all three check levels."""
    name = str(workload.get("Name", ""))
    namespace = str(workload.get("Namespace", "default")) or "default"
    kind = str(workload.get("Kind", ""))
    if not name or not kind:
        return []

    out: list[PolarisFinding] = []

    # Workload-level checks.
    workload_results = workload.get("Results")
    if isinstance(workload_results, dict):
        for check_id, check in workload_results.items():
            finding = _try_parse_check(
                check,
                check_id_fallback=str(check_id),
                workload_kind=kind,
                workload_name=name,
                namespace=namespace,
                container_name="",
                check_level="workload",
                detected_at=detected_at,
            )
            if finding is not None:
                out.append(finding)

    # Pod-level + container-level checks.
    pod = workload.get("PodResult")
    if isinstance(pod, dict):
        pod_results = pod.get("Results")
        if isinstance(pod_results, dict):
            for check_id, check in pod_results.items():
                finding = _try_parse_check(
                    check,
                    check_id_fallback=str(check_id),
                    workload_kind=kind,
                    workload_name=name,
                    namespace=namespace,
                    container_name="",
                    check_level="pod",
                    detected_at=detected_at,
                )
                if finding is not None:
                    out.append(finding)

        containers = pod.get("ContainerResults")
        if isinstance(containers, list):
            for container in containers:
                if not isinstance(container, dict):
                    continue
                container_name = str(container.get("Name", ""))
                container_results = container.get("Results")
                if not isinstance(container_results, dict):
                    continue
                for check_id, check in container_results.items():
                    finding = _try_parse_check(
                        check,
                        check_id_fallback=str(check_id),
                        workload_kind=kind,
                        workload_name=name,
                        namespace=namespace,
                        container_name=container_name,
                        check_level="container",
                        detected_at=detected_at,
                    )
                    if finding is not None:
                        out.append(finding)

    return out


def _try_parse_check(
    check: Any,
    *,
    check_id_fallback: str,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    container_name: str,
    check_level: str,
    detected_at: datetime,
) -> PolarisFinding | None:
    """Convert one Results.<check_id>={...} entry into a PolarisFinding."""
    if not isinstance(check, dict):
        return None
    success = check.get("Success")
    if not isinstance(success, bool) or success:
        return None  # passing check — not a finding

    check_id = str(check.get("ID", "")) or check_id_fallback
    if not check_id:
        return None

    severity_raw = str(check.get("Severity", "")).lower()
    if severity_raw not in {"danger", "warning"}:
        return None  # `ignore` and unknown values drop

    message = str(check.get("Message", ""))
    if not message:
        return None

    try:
        return PolarisFinding(
            check_id=check_id,
            message=message,
            severity=severity_raw,
            category=str(check.get("Category", "")),
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            check_level=check_level,
            detected_at=detected_at,
            unmapped=_collect_unmapped(check),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _collect_unmapped(check: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting Polaris fields not in the typed shape."""
    out: dict[str, Any] = {}
    for key in ("Details", "DetailedExplanation", "Conclusion"):
        if key in check:
            out[key] = check[key]
    return out


__all__ = [
    "PolarisFinding",
    "PolarisReaderError",
    "read_polaris",
]
