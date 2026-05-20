"""Scorer — Stage 5 (SCORE) of the D.5 7-stage pipeline.

Takes the detector outputs (already severity-graded per-detector) plus
the ``CorrelationResult`` from Stage 4 (CORRELATE), and produces a new
list of findings with severity uplifted by one level for every finding
that has at least one matching F.3 sibling-workspace finding.

Q4 rule (per plan):
- D.5 finding + F.3 finding on the same bucket → D.5 severity uplifts
  one level (cap at CRITICAL).
- D.5 finding with no F.3 correlation → unchanged severity.

Uplift order: INFO -> LOW -> MEDIUM -> HIGH -> CRITICAL -> CRITICAL.

The scorer DOES NOT introduce a new rule_id — it preserves the
detector's rule_id verbatim. It only adjusts ``severity_id`` /
``severity`` in the OCSF payload and adds a ``correlation_uplift``
entry to ``evidences``.

Pure function: no I/O, no module state. Output is a new tuple; the
input findings are not mutated.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from data_security.correlate import CorrelationResult
from data_security.schemas import (
    CloudPostureFinding,
    Severity,
    severity_to_id,
)

# One-level uplift order. CRITICAL caps at CRITICAL.
_UPLIFT: dict[Severity, Severity] = {
    Severity.INFO: Severity.LOW,
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


def apply_correlation_uplift(
    findings: Iterable[CloudPostureFinding],
    correlation: CorrelationResult,
) -> tuple[CloudPostureFinding, ...]:
    """Return a tuple of findings with severity uplifted per-finding when
    correlation matches exist.

    For each input finding:

    - If ``correlation.matches_for(finding.finding_id)`` is non-empty,
      the severity is uplifted one level (cap CRITICAL). The evidence
      payload gains a ``correlation_uplift`` entry recording the
      original severity, the new severity, and the list of matching
      F.3 finding-ids.
    - Otherwise the finding passes through unchanged (the same object
      reference — no defensive copy on the no-op path).
    """
    out: list[CloudPostureFinding] = []
    for finding in findings:
        f3_matches = correlation.matches_for(finding.finding_id)
        if not f3_matches:
            out.append(finding)
            continue
        out.append(_uplift_one(finding, f3_matches))
    return tuple(out)


def _uplift_one(
    finding: CloudPostureFinding,
    f3_matches: list[str],
) -> CloudPostureFinding:
    """Build a new ``CloudPostureFinding`` with bumped severity + an
    ``correlation_uplift`` evidence entry.
    """
    original_severity = finding.severity
    new_severity = _UPLIFT[original_severity]

    payload = finding.to_dict()
    payload["severity_id"] = severity_to_id(new_severity)
    payload["severity"] = new_severity.value.capitalize()

    correlation_evidence: dict[str, Any] = {
        "rule": "correlation_uplift",
        "source": "f3_cloud_posture",
        "original_severity": original_severity.value,
        "uplifted_severity": new_severity.value,
        "matched_f3_finding_ids": list(f3_matches),
    }

    # `evidences` is always present (build_finding sets it to [] when
    # evidence=None) — defensive isinstance/list copy to keep the
    # payload immutable to the caller and append the correlation entry.
    raw_evidences = payload.get("evidences")
    if isinstance(raw_evidences, list):
        new_evidences = [*raw_evidences, correlation_evidence]
    else:
        new_evidences = [correlation_evidence]
    payload["evidences"] = new_evidences

    return CloudPostureFinding(payload)
