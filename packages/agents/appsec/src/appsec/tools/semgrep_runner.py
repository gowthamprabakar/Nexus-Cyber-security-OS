"""Semgrep SAST scanner — async subprocess wrapper (D.14, B-1 PR8; Q-AppSec-5).

Q-AppSec-5 = Semgrep OSS. The OSS ``semgrep`` CLI is LGPL-2.1; invoking it as a
subprocess is license-compatible with our permissive posture (#23 clear). The
RULESET is operator-provisioned (``config``) and license-vetted separately — this
wrapper NEVER bundles rules and NEVER targets the Semgrep Pro registry (#23).

Operator-provisioned-binary model (``shutil.which``): absent binary degrades
gracefully (clean skip). ``semgrep scan --json --config <ruleset> <path>`` exits
non-zero when it finds issues, so a non-zero return code is NOT an error as long as
JSON parsed.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Default ruleset — Semgrep's curated CI pack (community, registry-hosted). The
#: operator may override; Pro rules (p/semgrep-pro, etc.) are intentionally NOT
#: used (#23 license posture). A local rules dir is also a valid config.
DEFAULT_SEMGREP_CONFIG = "p/ci"


class SemgrepError(RuntimeError):
    """Semgrep timed out or produced unparseable output."""


@dataclass
class SemgrepResult:
    """Parsed Semgrep output. ``payload`` is the raw JSON (``{results, errors}``)."""

    payload: dict[str, Any] = field(default_factory=dict)
    binary_present: bool = True


async def run_semgrep(
    repo_path: str | Path,
    *,
    config: str = DEFAULT_SEMGREP_CONFIG,
    timeout_sec: float = 900.0,
) -> SemgrepResult:
    """Run Semgrep against a local directory; parse JSON. Graceful if binary absent."""
    binary = shutil.which("semgrep")
    if binary is None:
        return SemgrepResult(payload={}, binary_present=False)

    args = ["scan", "--json", "--quiet", "--config", config, str(repo_path)]
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
        raise SemgrepError(f"semgrep timed out after {timeout_sec}s") from exc

    if not stdout_b.strip():
        return SemgrepResult(payload={})
    try:
        payload = json.loads(stdout_b)
    except json.JSONDecodeError as exc:
        raise SemgrepError(
            f"failed to parse semgrep json: {exc}; stderr={stderr_b.decode().strip()}"
        ) from exc
    return SemgrepResult(payload=payload if isinstance(payload, dict) else {})
