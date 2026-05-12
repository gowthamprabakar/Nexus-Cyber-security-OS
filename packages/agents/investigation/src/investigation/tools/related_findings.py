"""`find_related_findings` — cross-agent workspace reader (D.7 Task 5).

D.7's first tool that reads from **sibling-agent artifacts** instead of
a substrate store. Resolves the D.7 plan's Q3 (cross-agent finding
reads) — the operator pins `sibling_workspaces: tuple[Path, ...]` in
the contract, and D.7's driver passes those paths in. The tool reads
each sibling's `findings.json` and returns a typed tuple of
`RelatedFinding` shapes the investigation pipeline can correlate.

The schema D.7 sees from siblings is the same `FindingsReport` wrapper
the existing agents (D.2 / D.3 / F.3) emit:

    {
      "agent": "runtime_threat",
      "agent_version": "0.1.0",
      "customer_id": "01HV0...",
      "run_id": "01J7...",
      "findings": [<list of OCSF-shape dicts>]
    }

`RelatedFinding` carries the cross-cutting fields D.7 routes on
(`source_agent`, `source_run_id`, `class_uid`) plus the raw `payload`
dict (so D.7 doesn't have to know each sibling's specific finding
schema). Downstream stages of the pipeline route on `class_uid` and
dispatch into class-specific synthesizers.

Per ADR-005 the filesystem read happens in `asyncio.to_thread` so the
agent driver can fan it out via `asyncio.TaskGroup` alongside the
audit-trail query (Task 3) and memory-walk (Task 4) tools.

**Forgiving on every failure mode.** Missing workspace, missing
`findings.json`, malformed JSON, or `findings: []` → that workspace
contributes zero `RelatedFinding`s but doesn't poison the others.
Same posture as F.6's `audit_jsonl_read` (drop bad lines, keep good
ones) — in v0.1, a single corrupt sibling must not jam an
incident-response export.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RelatedFinding:
    """One OCSF-shape finding read from a sibling agent's workspace."""

    source_agent: str
    source_run_id: str
    class_uid: int
    payload: dict[str, Any] = field(default_factory=dict)


async def find_related_findings(
    *,
    sibling_workspaces: Sequence[Path],
) -> tuple[RelatedFinding, ...]:
    """Read findings.json from each sibling workspace; return the merged tuple.

    The function fans out the per-workspace reads via
    `asyncio.to_thread` so a slow filesystem path doesn't block the
    others. Workspaces with missing or malformed findings.json are
    silently skipped (with a structlog warning).
    """
    if not sibling_workspaces:
        return ()

    chunks = await asyncio.gather(*(asyncio.to_thread(_read_one, ws) for ws in sibling_workspaces))
    flat: list[RelatedFinding] = []
    for chunk in chunks:
        flat.extend(chunk)
    return tuple(flat)


def _read_one(workspace: Path) -> tuple[RelatedFinding, ...]:
    findings_path = workspace / "findings.json"
    if not findings_path.is_file():
        return ()
    try:
        report = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _LOG.warning("skipping malformed findings.json at %s: %s", findings_path, exc)
        return ()
    if not isinstance(report, dict):
        return ()

    source_agent = str(report.get("agent", ""))
    source_run_id = str(report.get("run_id", ""))
    if not source_agent or not source_run_id:
        # The wrapper is malformed; skip the whole file.
        return ()

    raw_findings = report.get("findings", []) or []
    if not isinstance(raw_findings, list):
        return ()

    out: list[RelatedFinding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        class_uid_raw = raw.get("class_uid")
        if not isinstance(class_uid_raw, int):
            continue
        out.append(
            RelatedFinding(
                source_agent=source_agent,
                source_run_id=source_run_id,
                class_uid=class_uid_raw,
                payload=raw,
            )
        )
    return tuple(out)


__all__ = ["RelatedFinding", "find_related_findings"]
