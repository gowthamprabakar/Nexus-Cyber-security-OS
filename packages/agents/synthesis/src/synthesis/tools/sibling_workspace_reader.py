"""``read_sibling_workspaces`` — fan-out filesystem reader for D.13's three sources.

Reads ``findings.json`` from the three operator-pinned sibling-agent
workspaces D.13 narrates over (per Q2 of the D.13 plan):

  - D.7 Investigation conclusions (narrative spine).
  - D.6 Compliance posture (compliance section).
  - F.3 Cloud Posture (technical-details fallback).

Per ADR-005 the per-workspace filesystem reads happen in
``asyncio.to_thread`` so the agent driver (Task 9) can fan them out
via ``asyncio.TaskGroup`` against a single Stage-1 INGEST span.

**Forgiving on every failure mode.** Missing workspace, missing
``findings.json``, malformed JSON, or ``findings: []`` -> that
source contributes zero entries but doesn't poison the others. Same
posture as D.7's ``find_related_findings`` and D.8's correlators.

**Q6 reminder.** This reader returns raw OCSF dicts. The Stage 2
ENRICH step (Task 4) is responsible for filtering out matched-text
substrings before they reach the LLM prompt. The reader does NOT
sanitise -- it's the wire-shape boundary, not the narrative-safety
boundary.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SiblingFindings:
    """Bundle of the three sibling-agent finding lists.

    Each list contains the raw wrapped OCSF dicts from the
    corresponding sibling agent's ``findings.json``. Empty list when
    that sibling workspace was not pinned, missing, or malformed.
    """

    investigation: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    compliance: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    cloud_posture: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def total_findings(self) -> int:
        return len(self.investigation) + len(self.compliance) + len(self.cloud_posture)

    @property
    def any_source_present(self) -> bool:
        return self.total_findings > 0 or bool(
            self.investigation or self.compliance or self.cloud_posture
        )


async def read_sibling_workspaces(
    *,
    investigation_workspace: Path | None,
    compliance_workspace: Path | None,
    cloud_posture_workspace: Path | None,
) -> SiblingFindings:
    """Read findings.json from each of D.13's three sibling workspaces.

    Each per-workspace read happens in ``asyncio.to_thread`` and runs
    concurrently via ``asyncio.gather``. Skipped workspaces (None
    path) contribute the empty tuple. Workspaces with missing /
    malformed findings.json are silently skipped with a structlog
    warning.
    """
    investigation, compliance, cloud_posture = await asyncio.gather(
        asyncio.to_thread(_read_one, investigation_workspace),
        asyncio.to_thread(_read_one, compliance_workspace),
        asyncio.to_thread(_read_one, cloud_posture_workspace),
    )
    return SiblingFindings(
        investigation=tuple(investigation),
        compliance=tuple(compliance),
        cloud_posture=tuple(cloud_posture),
    )


def _read_one(workspace: Path | None) -> tuple[dict[str, Any], ...]:
    """Read findings.json from a single workspace; forgiving on every failure."""
    if workspace is None:
        return ()
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

    raw_findings = report.get("findings", []) or []
    if not isinstance(raw_findings, list):
        return ()

    out: list[dict[str, Any]] = []
    for raw in raw_findings:
        if isinstance(raw, dict):
            out.append(raw)
    return tuple(out)


__all__ = ["SiblingFindings", "read_sibling_workspaces"]
