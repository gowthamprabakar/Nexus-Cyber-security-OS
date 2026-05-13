"""`read_kube_bench` — filesystem ingest for kube-bench JSON output.

Reads a kube-bench (`kube-bench --json`) export and converts each
individual test result into a typed `KubeBenchFinding`. Per ADR-005 the
filesystem read happens on `asyncio.to_thread`; the wrapper is `async`
for TaskGroup fan-out.

**kube-bench JSON shape** (canonical):

```json
{
  "Controls": [
    {
      "id": "1",
      "version": "1.7",
      "detected_version": "1.27",
      "text": "Master Node Security Configuration",
      "node_type": "master",
      "tests": [
        {
          "section": "1.1",
          "desc": "Master Node Configuration Files",
          "results": [
            {
              "test_number": "1.1.1",
              "test_desc": "Ensure ...",
              "audit": "stat -c %a /etc/...",
              "status": "FAIL",
              "actual_value": "777",
              "scored": true,
              "remediation": "Run the below command...",
              "severity": "critical"  // optional; some profiles set this
            }
          ]
        }
      ]
    }
  ]
}
```

Also supports a **bare-array** top-level: `[{control...}, ...]` (older
kube-bench versions / hand-rolled exports).

**Filtering**: only `FAIL` and `WARN` statuses become findings. `PASS`
and `INFO` are dropped — those mean the control is satisfied. Records
with non-string status or missing `test_number` are dropped.

**Forgiving** on malformed entries — drops single records, not the whole
file. Top-level malformed JSON raises `KubeBenchReaderError` explicitly.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class KubeBenchReaderError(RuntimeError):
    """The kube-bench JSON feed could not be read."""


class KubeBenchFinding(BaseModel):
    """One kube-bench test result (FAIL or WARN)."""

    control_id: str = Field(min_length=1)  # e.g. "1.1.1"
    control_text: str = Field(min_length=1)  # e.g. "Ensure that the API server..."
    section_id: str = Field(default="")  # e.g. "1.1"
    section_desc: str = Field(default="")  # e.g. "Master Node Configuration Files"
    node_type: str = Field(default="")  # master / worker / etcd / controlplane / policies
    status: str = Field(pattern=r"^(FAIL|WARN)$")
    severity_marker: str = Field(default="")  # "critical" if upstream sets it
    audit: str = Field(default="")  # the audit command run
    actual_value: str = Field(default="")
    remediation: str = Field(default="")
    scored: bool = Field(default=True)
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_kube_bench(*, path: Path) -> tuple[KubeBenchFinding, ...]:
    """Read a kube-bench JSON file and return the parsed FAIL/WARN findings."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[KubeBenchFinding, ...]:
    if not path.exists():
        raise KubeBenchReaderError(f"kube-bench json not found: {path}")
    if not path.is_file():
        raise KubeBenchReaderError(f"kube-bench json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise KubeBenchReaderError(f"kube-bench json is malformed: {exc}") from exc

    controls = _extract_controls(blob)
    detected_at = datetime.now(UTC)
    out: list[KubeBenchFinding] = []
    for control in controls:
        for finding in _walk_control(control, detected_at=detected_at):
            out.append(finding)
    return tuple(out)


def _extract_controls(blob: Any) -> list[dict[str, Any]]:
    """Pull the `Controls` array out of the top-level JSON (or accept a bare array)."""
    if isinstance(blob, dict):
        controls = blob.get("Controls")
        if isinstance(controls, list):
            return [c for c in controls if isinstance(c, dict)]
        return []
    if isinstance(blob, list):
        return [c for c in blob if isinstance(c, dict)]
    return []


def _walk_control(
    control: dict[str, Any],
    *,
    detected_at: datetime,
) -> list[KubeBenchFinding]:
    """Walk one Controls[] entry, flattening tests[].results[] into findings."""
    node_type = str(control.get("node_type", ""))
    tests = control.get("tests")
    if not isinstance(tests, list):
        return []

    out: list[KubeBenchFinding] = []
    for test in tests:
        if not isinstance(test, dict):
            continue
        section_id = str(test.get("section", ""))
        section_desc = str(test.get("desc", ""))
        results = test.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            finding = _try_parse_result(
                result,
                section_id=section_id,
                section_desc=section_desc,
                node_type=node_type,
                detected_at=detected_at,
            )
            if finding is not None:
                out.append(finding)
    return out


def _try_parse_result(
    result: dict[str, Any],
    *,
    section_id: str,
    section_desc: str,
    node_type: str,
    detected_at: datetime,
) -> KubeBenchFinding | None:
    """Convert one results[] entry into a KubeBenchFinding (FAIL/WARN only)."""
    status_raw = result.get("status")
    if not isinstance(status_raw, str):
        return None
    status = status_raw.upper()
    if status not in {"FAIL", "WARN"}:
        return None

    test_number = str(result.get("test_number", ""))
    if not test_number:
        return None

    test_desc = str(result.get("test_desc", ""))
    if not test_desc:
        return None

    try:
        return KubeBenchFinding(
            control_id=test_number,
            control_text=test_desc,
            section_id=section_id,
            section_desc=section_desc,
            node_type=node_type,
            status=status,
            severity_marker=str(result.get("severity", "")),
            audit=str(result.get("audit", "")),
            actual_value=str(result.get("actual_value", "")),
            remediation=str(result.get("remediation", "")),
            scored=bool(result.get("scored", True)),
            detected_at=detected_at,
            unmapped=_collect_unmapped(result),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _collect_unmapped(result: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting kube-bench fields not in the typed shape."""
    out: dict[str, Any] = {}
    for key in (
        "audit_env",
        "AuditConfig",
        "AuditConfigEnv",
        "test_info",
        "type",
        "expected_result",
        "IsMultiple",
    ):
        if key in result:
            out[key] = result[key]
    return out


__all__ = [
    "KubeBenchFinding",
    "KubeBenchReaderError",
    "read_kube_bench",
]
