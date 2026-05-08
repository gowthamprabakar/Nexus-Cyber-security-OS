"""Prowler 5.x subprocess wrapper. Returns parsed JSON findings."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ProwlerError(RuntimeError):
    """Prowler exited non-zero or produced unparseable output."""


@dataclass
class ProwlerResult:
    raw_findings: list[dict[str, Any]] = field(default_factory=list)


def run_prowler_aws(
    account_id: str,
    region: str,
    output_dir: Path,
    min_severity: str = "info",
    profile: str | None = None,
    timeout_sec: int = 1800,
) -> ProwlerResult:
    """Run Prowler against an AWS account/region. Returns raw OCSF findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = shutil.which("prowler") or "prowler"
    args = [
        binary,
        "aws",
        "--region",
        region,
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        str(output_dir),
        "--no-banner",
    ]
    if profile:
        args += ["--profile", profile]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_sec)  # noqa: S603
    if proc.returncode != 0:
        raise ProwlerError(f"prowler exited {proc.returncode}: {proc.stderr.strip()}")

    json_files = sorted(output_dir.glob("*.ocsf.json"))
    if not json_files:
        raise ProwlerError(f"no prowler json output in {output_dir}")
    raw = json.loads(json_files[-1].read_text())

    threshold = _SEVERITY_ORDER.get(min_severity.lower(), 0)
    filtered = [
        f
        for f in raw
        if _SEVERITY_ORDER.get(str(f.get("Severity", "info")).lower(), 0) >= threshold
    ]
    return ProwlerResult(raw_findings=filtered)
