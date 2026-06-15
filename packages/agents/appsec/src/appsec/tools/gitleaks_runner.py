"""gitleaks secrets-in-code scanner — async subprocess wrapper (D.14, B-1 PR3).

Q-AppSec-4 = gitleaks (MIT). Operator-provisioned-binary model (shutil.which);
absent binary degrades gracefully. gitleaks writes its JSON report to a file
(``--report-path``), so the wrapper points it at a temp file and reads it back.
gitleaks exits non-zero when it finds leaks → ``--exit-code 0`` makes "leaks found"
a success; only a genuine failure (no report produced) raises.

The wrapper returns the RAW gitleaks finding list — redaction (dropping the
matched ``Secret``/``Match`` plaintext) happens in the normalizer, never here in a
way that persists plaintext.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class GitleaksError(RuntimeError):
    """gitleaks timed out or produced no parseable report."""


@dataclass
class GitleaksResult:
    """Parsed gitleaks output. ``payload`` is the raw JSON list of findings."""

    payload: list[dict[str, Any]] = field(default_factory=list)
    binary_present: bool = True


async def run_gitleaks(repo_path: str | Path, *, timeout_sec: float = 600.0) -> GitleaksResult:
    """Run gitleaks against a local directory; parse its JSON report.

    Missing binary → empty result with ``binary_present=False``. "Leaks found"
    (non-zero exit) is not an error (``--exit-code 0``); a missing report is.
    """
    binary = shutil.which("gitleaks")
    if binary is None:
        return GitleaksResult(payload=[], binary_present=False)

    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "gitleaks.json"
        args = [
            "dir",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            "--exit-code",
            "0",
        ]
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise GitleaksError(f"gitleaks timed out after {timeout_sec}s") from exc

        if not report_path.is_file():
            raise GitleaksError(
                f"gitleaks produced no report at {report_path}; stderr={stderr_b.decode().strip()}"
            )
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError as exc:
            raise GitleaksError(f"failed to parse gitleaks json report: {exc}") from exc
    return GitleaksResult(payload=payload if isinstance(payload, list) else [])
