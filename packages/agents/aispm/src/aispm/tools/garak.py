"""Garak prompt-injection probe connector (D.11 AI-SPM PR4, operator Q2/Q6).

Garak (NVIDIA's LLM vulnerability scanner) is an external **CLI** red-teamer. It is wrapped
as a subprocess (the trivy/prowler pattern) — **never** a Python dependency, so no torch
enters the core (Q6). Probing is **active** (sends adversarial prompts → cost + safety), so
the agent runs it **only** behind the ``NEXUS_LIVE_AISPM_PROBE`` gate against a discovered
cloud endpoint (Q4: cloud creds; no external API key). Default-off → byte-identical.

A thin :class:`GarakRunner` protocol is the seam: the live ``_SubprocessGarakRunner`` shells
out to ``garak`` and parses its ``report.jsonl``; tests inject a fake runner returning canned
report entries. :func:`results_from_entries` is the pure parse.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class GarakError(RuntimeError):
    """The garak subprocess failed to run."""


class GarakRunner(Protocol):
    """Produces garak report entries for a target — real subprocess or fake."""

    async def probe(self, *, target: str) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class GarakProbeResult:
    probe: str
    detector: str
    failed: int  # prompts where the model failed the safety detector (= injection succeeded)
    total: int


def results_from_entries(entries: list[dict[str, Any]]) -> list[GarakProbeResult]:
    """Pure parse of garak ``report.jsonl`` ``eval`` entries → typed results."""
    out: list[GarakProbeResult] = []
    for e in entries:
        if e.get("entry_type") != "eval":
            continue
        total = int(e.get("total", 0))
        passed = int(e.get("passed", 0))
        out.append(
            GarakProbeResult(
                probe=str(e.get("probe", "")),
                detector=str(e.get("detector", "")),
                failed=max(0, total - passed),
                total=total,
            )
        )
    return out


class _SubprocessGarakRunner:
    """Live garak CLI runner (gated; NOT exercised in CI). Parses report.jsonl."""

    def __init__(self, *, output_dir: Path, timeout_sec: float = 900.0) -> None:
        self._output_dir = output_dir
        self._timeout = timeout_sec

    async def probe(self, *, target: str) -> list[dict[str, Any]]:
        import shutil

        self._output_dir.mkdir(parents=True, exist_ok=True)
        report = self._output_dir / "garak.report.jsonl"
        binary = shutil.which("garak") or "garak"
        # Probe the discovered model via garak's REST generator; injection/jailbreak probes.
        args = [
            "--model_type",
            "rest",
            "--model_name",
            target,
            "--probes",
            "promptinject,dan,latentinjection",
            "--report_prefix",
            str(self._output_dir / "garak"),
        ]
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise GarakError(f"garak timed out after {self._timeout}s") from exc
        if not report.exists():
            raise GarakError(f"garak produced no report ({stderr_b.decode()[:200]})")
        entries: list[dict[str, Any]] = []
        for line in report.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
        return entries


async def run_garak(
    *,
    target: str,
    runner: GarakRunner | None = None,
    output_dir: Path | None = None,
) -> list[GarakProbeResult]:
    """Probe ``target`` with garak and return typed per-probe results."""
    actual = runner or _SubprocessGarakRunner(output_dir=output_dir or Path("garak_out"))
    return results_from_entries(await actual.probe(target=target))


__all__ = [
    "GarakError",
    "GarakProbeResult",
    "GarakRunner",
    "results_from_entries",
    "run_garak",
]
