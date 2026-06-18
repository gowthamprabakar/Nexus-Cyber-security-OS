"""Stage-5 SCORE — canonical severity scorer for ComplianceFindings.

Per Q9 of the D.9 v0.1 plan: a deterministic, table-driven severity
re-stamp that runs after the Stage-4 aggregator. Stages 6 + 7 (Stage
5 SUMMARIZE + Stage 7 HANDOFF) operate on the scored output -- the
scorer is the **single canonical source of truth** for D.9 v0.1
severity. Correlators (Tasks 6 + 7) and the aggregator (Task 8) emit
at their natural defaults; the scorer is what downstream consumers
see.

**Scoring table** (mirrors :func:`compliance.schemas.severity_for_level`):

  - Level 1 + required    -> ``Severity.HIGH``
  - Level 1 + recommended -> ``Severity.MEDIUM``
  - Level 2 + required    -> ``Severity.MEDIUM``
  - Level 2 + recommended -> ``Severity.LOW``

The control's ``level`` + ``required`` flag come from
``evidence.control.{level, required}`` -- the Stage-3 correlators
plant those values, and the aggregator preserves the first
contributor's values verbatim. Missing / malformed control evidence
collapses the score to ``Severity.LOW`` (conservative -- a
mis-formed compliance finding shouldn't be treated as a CRITICAL
incident).

**Re-stamping mechanic.** Identical pattern to D.8's scorer:
``ComplianceFinding`` wraps an immutable OCSF dict; the scorer
rebuilds the wrapped dict with new ``severity_id`` + ``severity``
string only if the canonical severity differs from the input. The
envelope and all other payload fields stay verbatim so the OCSF
``finding_info.uid`` is stable across re-stamps (D.7 cross-
references survive).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from compliance.schemas import (
    ComplianceFinding,
    ControlLevel,
    Severity,
    severity_for_level,
    severity_to_id,
)

# Conservative fallback when evidence.control is missing/malformed.
_FALLBACK_SEVERITY = Severity.LOW


def score_severity_from_evidence(evidence: dict[str, Any]) -> Severity:
    """Pure: derive canonical Severity from an evidence-shaped dict.

    Looks for ``evidence.control.level`` (``"level_1"`` /
    ``"level_2"``) and ``evidence.control.required`` (``bool``).
    Missing/malformed -> ``Severity.LOW``.
    """
    if not isinstance(evidence, dict):
        return _FALLBACK_SEVERITY
    control = evidence.get("control")
    if not isinstance(control, dict):
        return _FALLBACK_SEVERITY
    level_raw = control.get("level")
    if not isinstance(level_raw, str):
        return _FALLBACK_SEVERITY
    try:
        level = ControlLevel(level_raw)
    except ValueError:
        return _FALLBACK_SEVERITY
    required = bool(control.get("required", True))
    return severity_for_level(level, required=required)


def score_findings(
    findings: Sequence[ComplianceFinding],
) -> tuple[ComplianceFinding, ...]:
    """Re-stamp severity on each finding via the canonical table.

    Findings whose current severity already matches the canonical
    table value are returned unchanged (identity preserved). Findings
    that need re-stamping get a new ``ComplianceFinding`` wrapping a
    payload identical to the input except for ``severity_id`` and
    ``severity`` string label.
    """
    out: list[ComplianceFinding] = []
    for finding in findings:
        payload = finding.to_dict()
        evidence = _first_evidence(payload)
        canonical = score_severity_from_evidence(evidence)
        if canonical == finding.severity:
            out.append(finding)
            continue
        out.append(_restamp(payload, canonical))
    return tuple(out)


def _first_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    evs = payload.get("evidences") or []
    if isinstance(evs, list) and evs and isinstance(evs[0], dict):
        return dict(evs[0])
    return {}


def _restamp(payload: dict[str, Any], severity: Severity) -> ComplianceFinding:
    new_payload = dict(payload)
    new_payload["severity_id"] = severity_to_id(severity)
    new_payload["severity"] = severity.value.capitalize()
    return ComplianceFinding(new_payload)


__all__ = ["score_findings", "score_severity_from_evidence"]
