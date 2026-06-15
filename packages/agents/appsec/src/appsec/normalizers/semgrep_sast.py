"""Semgrep output → AppSecFinding (SAST) — D.14 B-1 PR8.

Maps Semgrep ``results[]`` to ``AppSecFinding`` (SAST discriminator → OCSF 2003 per
the Option-1 unification: all D.14 findings share class 2003, distinguished by
``AppSecFindingType``). Carries check_id + message + file:line; does NOT carry the
matched code snippet (``extra.lines``) into the finding — location + rule is enough
and keeps the wire surface lean.
"""

from __future__ import annotations

import re
from typing import Any

from appsec.schemas import AppSecFinding, AppSecFindingType, Severity

_FINDING_ID_INVALID = re.compile(r"[^a-zA-Z0-9._-]")

_SEMGREP_SEVERITY: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _to_severity(raw: Any) -> Severity:
    if isinstance(raw, str):
        return _SEMGREP_SEVERITY.get(raw.upper(), Severity.MEDIUM)
    return Severity.MEDIUM


def _location(result: dict[str, Any]) -> str:
    path = str(result.get("path", "")).lstrip("/")
    start = result.get("start")
    line = start.get("line") if isinstance(start, dict) else None
    return f"{path}:{line}" if line is not None else path


def _finding_id(repo_slug: str, check_id: str, location: str) -> str:
    raw = f"APPSEC-SAST-{check_id}-{repo_slug}-{location}"
    return _FINDING_ID_INVALID.sub("_", raw)[:200]


def semgrep_to_findings(payload: dict[str, Any], *, repo_slug: str) -> list[AppSecFinding]:
    """Map Semgrep ``results`` to ``AppSecFinding`` SAST rows (defensive)."""
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    findings: list[AppSecFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        check_id = str(result.get("check_id", "")) or "unknown"
        extra_raw = result.get("extra")
        extra = extra_raw if isinstance(extra_raw, dict) else {}
        message = str(extra.get("message", "")) or check_id
        location = _location(result)
        findings.append(
            AppSecFinding(
                finding_id=_finding_id(repo_slug, check_id, location),
                finding_type=AppSecFindingType.SAST_FINDING,
                rule_id=check_id,
                severity=_to_severity(extra.get("severity")),
                title=message[:200],
                description=f"Semgrep {check_id} matched in {location} ({repo_slug}): {message}",
                repo_slug=repo_slug,
                location=location,
            )
        )
    return findings


__all__ = ["semgrep_to_findings"]
