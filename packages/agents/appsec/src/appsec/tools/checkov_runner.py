"""Checkov IaC scanner — async subprocess wrapper (D.14, B-1 PR2; Q-AppSec-3).

Operator-provisioned binary model (same as Trivy/Prowler/osquery): ``shutil.which``
locates ``checkov``; absence degrades gracefully (clean skip, not a crash). Runs
``checkov -d <path> -o json --compact`` and returns the parsed payload (a dict or,
for multi-framework scans, a list of dicts — the normalizer handles both).
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CheckovError(RuntimeError):
    """Checkov timed out or produced unparseable output."""


@dataclass
class CheckovResult:
    """Parsed Checkov output. ``payload`` is the raw JSON (dict or list)."""

    payload: Any = field(default_factory=dict)
    binary_present: bool = True


async def run_checkov(repo_path: str | Path, *, timeout_sec: float = 600.0) -> CheckovResult:
    """Run Checkov against a local directory; parse JSON. Graceful if binary absent.

    Checkov exits non-zero when it finds failures, so a non-zero return code is NOT
    treated as an error as long as JSON parsed. Missing binary → empty result with
    ``binary_present=False`` (operator must provision checkov for the live lane).
    """
    binary = shutil.which("checkov")
    if binary is None:
        return CheckovResult(payload={}, binary_present=False)

    args = ["-d", str(repo_path), "-o", "json", "--compact"]
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise CheckovError(f"checkov timed out after {timeout_sec}s") from exc

    if not stdout_b.strip():
        # No output (e.g. nothing to scan) — empty, not an error.
        return CheckovResult(payload={})
    try:
        payload = json.loads(stdout_b)
    except json.JSONDecodeError as exc:
        raise CheckovError(
            f"failed to parse checkov json output: {exc}; stderr={stderr_b.decode().strip()}"
        ) from exc
    return CheckovResult(payload=payload)
