"""F.3 cross-correlation — annotate D.5 findings with sibling F.3 findings.

Stage 4 (CORRELATE) of the D.5 7-stage pipeline. Optional: only runs
when the operator pins ``--cloud-posture-workspace`` to a sibling F.3
workspace directory containing ``findings.json``. When the flag is
absent or the file isn't present, D.5 runs standalone and no
correlation annotations are produced.

Q4 resolution (per plan):
- Operator-pinned via ``--cloud-posture-workspace`` flag. NOT autodiscover.
- Match by bucket ARN (the only stable cross-agent key in v0.1).
- Annotations feed the SCORE stage (Task 10), which applies severity
  uplift. This module does NOT mutate the findings — it returns a
  ``CorrelationResult`` map.

The reader is forgiving: missing workspace file, malformed JSON,
unrecognised shape — all yield empty results, not exceptions. The
agent driver emits a one-line warning (Task 12) but does not fail
the run on F.3 absence.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from data_security.schemas import CloudPostureFinding

# F.3 / multi-cloud-posture / k8s-posture write this filename inside
# their workspace. Convention from ADR-007.
F3_FINDINGS_FILENAME = "findings.json"


@dataclass(frozen=True)
class CorrelationResult:
    """Per-D.5-finding map of correlated F.3 finding IDs.

    Consumed by the SCORE stage (Task 10): when a D.5 finding has at
    least one matching F.3 finding-id, the scorer uplifts severity by
    one level (capped at CRITICAL). The mapping is keyed by D.5
    finding-id (the unique identifier from ``CSPM-AWS-XYZ-NNN-...``).

    The ``raw_f3_finding_count`` is recorded for the verification
    record's coverage delta — it's the total finding count from the
    sibling workspace, regardless of whether they matched D.5 buckets.
    """

    matches: dict[str, list[str]] = field(default_factory=dict)
    """``d5_finding_id`` → list of matching F.3 ``finding_id`` values."""

    raw_f3_finding_count: int = 0
    """Total F.3 findings observed (matched or not)."""

    def matches_for(self, d5_finding_id: str) -> list[str]:
        """Return the list of F.3 finding-IDs that match the given D.5
        finding. Empty list when no match.
        """
        return list(self.matches.get(d5_finding_id, []))

    @property
    def matched_d5_finding_count(self) -> int:
        return sum(1 for v in self.matches.values() if v)


async def read_f3_findings(workspace_path: Path) -> tuple[dict[str, Any], ...]:
    """Read ``findings.json`` from a sibling F.3 cloud-posture workspace.

    Returns the unwrapped list of finding dicts (each is a wrapped OCSF
    payload — same shape D.5 emits). Returns empty tuple if the file
    is missing, malformed, or unrecognised shape.

    Per ADR-005 the filesystem read goes through ``asyncio.to_thread``.
    """
    return await asyncio.to_thread(_read_sync, workspace_path)


def _read_sync(workspace_path: Path) -> tuple[dict[str, Any], ...]:
    findings_path = workspace_path / F3_FINDINGS_FILENAME
    if not findings_path.exists() or not findings_path.is_file():
        return ()

    try:
        with findings_path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except (json.JSONDecodeError, OSError):
        return ()

    return tuple(_extract_findings(blob))


def _extract_findings(blob: Any) -> list[dict[str, Any]]:
    """Pull the findings list from a FindingsReport-shaped or bare-list
    top-level JSON. Forgiving on shape drift.
    """
    if isinstance(blob, dict):
        raw = blob.get("findings", [])
        if isinstance(raw, list):
            return [f for f in raw if isinstance(f, dict)]
        return []
    if isinstance(blob, list):
        return [f for f in blob if isinstance(f, dict)]
    return []


def correlate_with_f3(
    d5_findings: Iterable[CloudPostureFinding],
    f3_findings: Iterable[dict[str, Any]],
) -> CorrelationResult:
    """Match D.5 findings against F.3 findings by bucket ARN.

    For each D.5 finding, scans the F.3 findings list for any finding
    whose ``resources[*].uid`` (the OCSF ARN field) matches the D.5
    finding's bucket ARN. Returns a ``CorrelationResult`` mapping
    each D.5 finding-id to the list of matching F.3 finding-ids.

    Pure function: no I/O, no module state.

    ``f3_findings`` are raw wrapped OCSF dicts (the shape ``read_f3
    _findings`` returns). The D.5 findings are typed
    ``CloudPostureFinding`` objects.
    """
    d5_findings_list = list(d5_findings)
    f3_findings_list = list(f3_findings)

    # Build an ARN -> list[f3_finding_id] index once for O(D) lookup
    # rather than O(D * F) scanning per match.
    f3_index: dict[str, list[str]] = {}
    for f3 in f3_findings_list:
        f3_uid = _safe_get_finding_uid(f3)
        if not f3_uid:
            continue
        for arn in _safe_get_resource_arns(f3):
            f3_index.setdefault(arn, []).append(f3_uid)

    matches: dict[str, list[str]] = {}
    for d5_finding in d5_findings_list:
        d5_arns = _d5_finding_arns(d5_finding)
        matching_f3_ids: list[str] = []
        seen: set[str] = set()
        for arn in d5_arns:
            for f3_id in f3_index.get(arn, ()):
                if f3_id not in seen:
                    seen.add(f3_id)
                    matching_f3_ids.append(f3_id)
        if matching_f3_ids:
            matches[d5_finding.finding_id] = matching_f3_ids

    return CorrelationResult(
        matches=matches,
        raw_f3_finding_count=len(f3_findings_list),
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _safe_get_finding_uid(payload: dict[str, Any]) -> str | None:
    """Extract the finding-id from a wrapped OCSF dict. None if absent."""
    finding_info = payload.get("finding_info")
    if not isinstance(finding_info, dict):
        return None
    uid = finding_info.get("uid")
    return uid if isinstance(uid, str) and uid else None


def _safe_get_resource_arns(payload: dict[str, Any]) -> list[str]:
    """Extract resource ARNs from a wrapped OCSF dict's ``resources`` array.

    OCSF v1.3 ResourceDetails has ``uid`` carrying the ARN. Returns
    empty list if the structure is malformed.
    """
    resources = payload.get("resources", [])
    if not isinstance(resources, list):
        return []
    out: list[str] = []
    for r in resources:
        if isinstance(r, dict):
            uid = r.get("uid")
            if isinstance(uid, str) and uid:
                out.append(uid)
    return out


def _d5_finding_arns(finding: CloudPostureFinding) -> list[str]:
    """Extract resource ARNs from a typed D.5 finding."""
    return [str(r.get("uid")) for r in finding.resources if r.get("uid")]
