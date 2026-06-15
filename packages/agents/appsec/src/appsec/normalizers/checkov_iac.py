"""Checkov output → AppSecFinding (IaC misconfiguration) — D.14 B-1 PR2.

Defensively handles Checkov's two top-level shapes: a single ``{check_type,
results:{failed_checks:[...]}}`` dict, or a list of such dicts (multi-framework
scan). Only ``failed_checks`` become findings. Missing/odd fields are skipped, so
one malformed row never poisons the batch.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from appsec.schemas import AppSecFinding, AppSecFindingType, Severity

_FINDING_ID_INVALID = re.compile(r"[^a-zA-Z0-9._-]")

_CHECKOV_SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def _iter_result_blocks(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for block in payload:
            if isinstance(block, dict):
                yield block
    elif isinstance(payload, dict):
        yield payload


def _to_severity(raw: Any) -> Severity:
    if isinstance(raw, str):
        return _CHECKOV_SEVERITY.get(raw.upper(), Severity.MEDIUM)
    return Severity.MEDIUM  # checkov omits severity without a platform key


def _location(check: dict[str, Any]) -> str:
    file_path = str(check.get("file_path", "")).lstrip("/")
    line_range = check.get("file_line_range")
    if isinstance(line_range, list) and line_range:
        return f"{file_path}:{line_range[0]}"
    return file_path


def _finding_id(repo_slug: str, check_id: str, location: str) -> str:
    raw = f"APPSEC-IAC-{check_id}-{repo_slug}-{location}"
    return _FINDING_ID_INVALID.sub("_", raw)[:200]


def checkov_to_findings(payload: Any, *, repo_slug: str) -> list[AppSecFinding]:
    """Map Checkov ``failed_checks`` to ``AppSecFinding`` IaC-misconfiguration rows."""
    findings: list[AppSecFinding] = []
    for block in _iter_result_blocks(payload):
        results = block.get("results")
        if not isinstance(results, dict):
            continue
        failed = results.get("failed_checks")
        if not isinstance(failed, list):
            continue
        for check in failed:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("check_id", "")) or "UNKNOWN"
            check_name = str(check.get("check_name", "")) or check_id
            location = _location(check)
            resource = str(check.get("resource", ""))
            findings.append(
                AppSecFinding(
                    finding_id=_finding_id(repo_slug, check_id, location),
                    finding_type=AppSecFindingType.IAC_MISCONFIGURATION,
                    rule_id=check_id,
                    severity=_to_severity(check.get("severity")),
                    title=check_name,
                    description=(
                        f"Checkov {check_id} failed on {resource or location} "
                        f"in {repo_slug}: {check_name}"
                    ),
                    repo_slug=repo_slug,
                    location=location,
                )
            )
    return findings


__all__ = ["checkov_to_findings"]
