"""Stage-4 SCORE — canonical severity scorer for ThreatIntelFindings.

Per the D.8 v0.1 plan §Task 10: a deterministic, table-driven severity
re-stamp that runs after the three Stage-3 correlators emit. The
scorer is the single canonical source of truth for D.8 v0.1 severity;
correlators emit at their natural correlator-default severity but the
scorer is what downstream consumers see.

**Scoring table.**

  - ``CVE_IN_KEV_CATALOG``         -> ``Severity.CRITICAL``
  - ``IOC_MATCH_NETWORK`` (conf >= 0.8) -> ``Severity.HIGH``
  - ``IOC_MATCH_NETWORK`` (0.5 <= conf < 0.8) -> ``Severity.MEDIUM``
  - ``IOC_MATCH_NETWORK`` (conf < 0.5)        -> ``Severity.LOW``
  - ``IOC_MATCH_RUNTIME`` -- same confidence buckets as NETWORK.
  - ``ATTACK_TECHNIQUE_OBSERVED`` -> ``Severity.MEDIUM``

KEV listing is binary -- a CVE either is or isn't in the actively-
exploited catalog. v0.3 (per the D.8 version roadmap) replaces the
binary KEV flag with richer composite scoring (CVSS x EPSS x KEV x
asset-criticality).

The scorer is **pure** (no I/O, no side effects). It takes findings,
returns findings -- the agent driver (Task 12) calls
:func:`score_findings` between Stage 3 CORRELATE and Stage 5
SUMMARIZE.

**Re-stamping mechanic.** ``ThreatIntelFinding`` wraps an immutable
OCSF dict; the scorer rebuilds the wrapped dict with new
``severity_id`` + ``severity`` string if the canonical severity
differs from the correlator-emitted severity. The envelope and
all other payload fields are preserved verbatim (the OCSF
``finding_info.uid`` stays stable so D.7 cross-references survive
the re-stamp).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_intel.schemas import (
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    severity_to_id,
)

# IOC confidence thresholds. Tied directly to the correlator-emit table
# (see correlators/ioc_correlator_network.py + ioc_correlator_runtime.py).
_HIGH_CONFIDENCE_FLOOR = 0.8
_MEDIUM_CONFIDENCE_FLOOR = 0.5


def score_severity(finding_type: ThreatIntelFindingType, evidence: dict[str, Any]) -> Severity:
    """Return the canonical severity per the D.8 v0.1 scoring table.

    For IOC matches, the confidence is read from
    ``evidence["ioc_entry"]["confidence"]`` -- the standard shape the
    Task 8 and Task 9 correlators construct. Missing or malformed
    confidence values collapse to ``Severity.LOW`` (conservative).
    """
    if finding_type == ThreatIntelFindingType.CVE_IN_KEV_CATALOG:
        return Severity.CRITICAL
    if finding_type == ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED:
        return Severity.MEDIUM
    if finding_type in (
        ThreatIntelFindingType.IOC_MATCH_NETWORK,
        ThreatIntelFindingType.IOC_MATCH_RUNTIME,
    ):
        return _score_ioc_confidence(evidence)
    return Severity.LOW


def _score_ioc_confidence(evidence: dict[str, Any]) -> Severity:
    ioc_entry = evidence.get("ioc_entry") if isinstance(evidence, dict) else None
    if not isinstance(ioc_entry, dict):
        return Severity.LOW
    raw = ioc_entry.get("confidence")
    try:
        confidence = float(raw) if raw is not None else 0.0
    except (TypeError, ValueError):
        return Severity.LOW
    if confidence >= _HIGH_CONFIDENCE_FLOOR:
        return Severity.HIGH
    if confidence >= _MEDIUM_CONFIDENCE_FLOOR:
        return Severity.MEDIUM
    return Severity.LOW


def score_findings(
    findings: Sequence[ThreatIntelFinding],
) -> tuple[ThreatIntelFinding, ...]:
    """Re-stamp severity on each finding via the canonical table.

    Findings whose correlator-emitted severity already matches the
    canonical severity are returned unchanged (no rebuild). Findings
    that need re-stamping get a new ``ThreatIntelFinding`` wrapping a
    payload identical to the input except for ``severity_id`` and the
    ``severity`` string label.
    """
    out: list[ThreatIntelFinding] = []
    for finding in findings:
        payload = finding.to_dict()
        finding_type = _extract_finding_type(payload)
        if finding_type is None:
            out.append(finding)
            continue
        evidence = _first_evidence(payload)
        canonical = score_severity(finding_type, evidence)
        if canonical == finding.severity:
            out.append(finding)
            continue
        out.append(_restamp(payload, canonical))
    return tuple(out)


def _extract_finding_type(
    payload: dict[str, Any],
) -> ThreatIntelFindingType | None:
    types_list = payload.get("finding_info", {}).get("types") or []
    if not isinstance(types_list, list) or not types_list:
        return None
    raw = types_list[0]
    if not isinstance(raw, str):
        return None
    try:
        return ThreatIntelFindingType(raw)
    except ValueError:
        return None


def _first_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    evs = payload.get("evidences") or []
    if isinstance(evs, list) and evs and isinstance(evs[0], dict):
        return dict(evs[0])
    return {}


def _restamp(payload: dict[str, Any], severity: Severity) -> ThreatIntelFinding:
    new_payload = dict(payload)
    new_payload["severity_id"] = severity_to_id(severity)
    new_payload["severity"] = severity.value.capitalize()
    return ThreatIntelFinding(new_payload)


__all__ = ["score_findings", "score_severity"]
