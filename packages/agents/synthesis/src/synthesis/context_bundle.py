"""Stage-2 ENRICH — build the structured LLM-input ContextBundle.

Per Q6 of the D.13 plan, this stage is the **Q6 enforcement layer**.
The sibling-workspace reader (Task 3) returns raw OCSF dicts that may
carry classifier-matched substrings, raw bucket-object names, etc.
``build_context_bundle`` projects those raw dicts into a structured
``ContextBundle`` carrying:

- Severity counts (across all sources).
- Top-N findings from each source (finding_id + title + severity +
  cited control mapping where applicable).
- ``classifier_labels_found`` *arrays only* -- the label strings
  (``ssn``, ``credit_card``, ``aws_access_key``, ...) but **NEVER**
  the matched substring values.
- Investigation conclusions (D.7's narrative spine; deduplicated by
  finding-id; carries title + summary + cited finding_ids).
- Compliance control failures (D.6's per-control roll-ups; carries
  control_id + level + severity + contributing-source-finding count).

**Q6 invariant (load-bearing).** This module's API is the boundary
where matched-text leakage gets stopped. The Stage 4 REVIEW reviewer
(Task 7) catches anything the LLM hallucinates downstream, but the
*first* line of defence is here: only structured public-shape fields
flow into the LLM prompt context.

**Bounded sizes.** Top-N caps per source keep the LLM context budget
predictable. v0.1 caps:

- ``_MAX_FINDINGS_PER_SOURCE = 16``: top-N findings per sibling.
- ``_MAX_INVESTIGATION_CONCLUSIONS = 12``: investigation-conclusion
  entries.
- ``_MAX_CLASSIFIER_LABELS_PER_FINDING = 8``: classifier labels
  surfaced per finding.

These match the schema-layer ``_MAX_CITED_PER_SECTION`` / ``_MAX_
OUTLINE_SECTIONS`` caps so a single bundle can fit through one LLM
context window comfortably.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from synthesis.schemas import ContextBundle
from synthesis.tools.sibling_workspace_reader import SiblingFindings

# Per-source caps; v0.1 keeps context windows bounded.
_MAX_FINDINGS_PER_SOURCE = 16
_MAX_INVESTIGATION_CONCLUSIONS = 12
_MAX_CLASSIFIER_LABELS_PER_FINDING = 8

# Severity-bucket sort order; CRITICAL first then descending. Used to
# pick top-N when a source has more than ``_MAX_FINDINGS_PER_SOURCE``.
_SEVERITY_RANK: dict[int, int] = {
    5: 100,  # critical / fatal
    6: 100,
    4: 80,  # high
    3: 60,  # medium
    2: 40,  # low
    1: 20,  # informational
}


def build_context_bundle(
    sibling_findings: SiblingFindings,
    *,
    customer_id: str,
    scan_window_start: datetime,
    scan_window_end: datetime,
) -> ContextBundle:
    """Project the raw sibling findings into a structured LLM-input bundle.

    Per Q6, the projection drops every freeform-substring field and
    surfaces only structured public-shape data.
    """
    investigation_conclusions = _project_investigation(sibling_findings.investigation)
    compliance_failures = _project_compliance(sibling_findings.compliance)
    cloud_posture_findings = _project_cloud_posture(sibling_findings.cloud_posture)

    severity_counts = _accumulate_severity_counts(
        sibling_findings.investigation,
        sibling_findings.compliance,
        sibling_findings.cloud_posture,
    )
    total_findings = sibling_findings.total_findings

    return ContextBundle(
        customer_id=customer_id,
        scan_window_start=scan_window_start,
        scan_window_end=scan_window_end,
        investigation_conclusions=investigation_conclusions,
        compliance_failures=compliance_failures,
        cloud_posture_findings=cloud_posture_findings,
        severity_counts=severity_counts,
        total_findings=total_findings,
    )


# ---------------------------------------------------------------------------
# Per-source projection (each one strips matched-text fields)
# ---------------------------------------------------------------------------


def _project_investigation(
    raw: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    """D.7 Investigation findings -> conclusion summaries.

    D.7's payloads typically carry an investigation conclusion in
    ``finding_info.desc`` and a cited-finding-id list in
    ``evidence.related_finding_ids``. We surface those + the
    severity / finding-id, never raw evidence bodies.
    """
    top = _top_n(raw, _MAX_INVESTIGATION_CONCLUSIONS)
    out: list[dict[str, Any]] = []
    for payload in top:
        info = payload.get("finding_info") or {}
        evidence = _first_evidence(payload)
        related_ids = _safe_string_list(evidence.get("related_finding_ids"))
        out.append(
            {
                "finding_id": _safe_str(info.get("uid")),
                "title": _safe_str(info.get("title")),
                "summary": _safe_str(info.get("desc")),
                "severity_id": _safe_int(payload.get("severity_id")),
                "related_finding_ids": related_ids[:_MAX_FINDINGS_PER_SOURCE],
            }
        )
    return out


def _project_compliance(
    raw: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    """D.6 Compliance findings -> per-control roll-up summaries."""
    top = _top_n(raw, _MAX_FINDINGS_PER_SOURCE)
    out: list[dict[str, Any]] = []
    for payload in top:
        info = payload.get("finding_info") or {}
        compliance = payload.get("compliance") or {}
        evidence = _first_evidence(payload)
        control = evidence.get("control")
        control_meta: dict[str, Any] = {}
        if isinstance(control, dict):
            control_meta = {
                "framework": _safe_str(control.get("framework")),
                "control_id": _safe_str(control.get("control_id")),
                "level": _safe_str(control.get("level")),
                "required": bool(control.get("required", True)),
            }
        out.append(
            {
                "finding_id": _safe_str(info.get("uid")),
                "title": _safe_str(info.get("title")),
                "control": _safe_str(compliance.get("control")),
                "severity_id": _safe_int(payload.get("severity_id")),
                "contributor_count": _safe_int(evidence.get("contributor_count")),
                "control_meta": control_meta,
            }
        )
    return out


def _project_cloud_posture(
    raw: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    """F.3 Cloud Posture findings -> structured resource + classifier-label refs.

    **Q6 critical path.** F.3 payloads may carry D.5-style classifier
    labels inside ``evidence.classifier_labels_found`` (the labels
    themselves -- ``ssn``, ``credit_card``, ...). We surface those
    label strings BUT NOT any ``evidence.matched_text`` /
    ``evidence.bucket_objects[].matched_text`` /
    ``evidence.sample`` -shaped substring fields. The reviewer
    (Task 7) regex-guards the rendered narrative as a second line
    of defence.
    """
    top = _top_n(raw, _MAX_FINDINGS_PER_SOURCE)
    out: list[dict[str, Any]] = []
    for payload in top:
        info = payload.get("finding_info") or {}
        evidence = _first_evidence(payload)
        labels = _safe_string_list(evidence.get("classifier_labels_found"))
        resources = payload.get("resources") or []
        resource_arns: list[str] = []
        if isinstance(resources, list):
            for r in resources:
                if isinstance(r, dict):
                    arn = r.get("uid")
                    if isinstance(arn, str) and arn:
                        resource_arns.append(arn)
        out.append(
            {
                "finding_id": _safe_str(info.get("uid")),
                "title": _safe_str(info.get("title")),
                "severity_id": _safe_int(payload.get("severity_id")),
                "classifier_labels_found": labels[:_MAX_CLASSIFIER_LABELS_PER_FINDING],
                "resource_arns": resource_arns[:_MAX_FINDINGS_PER_SOURCE],
                # Intentionally NOT included: evidence.matched_text,
                # evidence.bucket_objects[].matched_text,
                # evidence.sample, finding_info.desc (which D.5
                # detectors may stuff with object-key fragments).
            }
        )
    return out


# ---------------------------------------------------------------------------
# Severity aggregation
# ---------------------------------------------------------------------------


def _accumulate_severity_counts(
    *finding_groups: tuple[dict[str, Any], ...],
) -> dict[str, int]:
    """Roll up severity counts across all sibling sources."""
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    bucket_by_id: dict[int, str] = {
        5: "critical",
        6: "critical",  # OCSF Fatal collapses to critical
        4: "high",
        3: "medium",
        2: "low",
        1: "info",
    }
    for group in finding_groups:
        for payload in group:
            sev_id = _safe_int(payload.get("severity_id"))
            label = bucket_by_id.get(sev_id)
            if label is not None:
                counts[label] += 1
    return counts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _top_n(raw: tuple[dict[str, Any], ...], n: int) -> tuple[dict[str, Any], ...]:
    """Pick top-N findings sorted by severity (CRITICAL first).

    Stable by finding_info.uid alphabetic order within severity
    band so reruns produce deterministic bundles.
    """
    if len(raw) <= n:
        return raw

    def key(payload: dict[str, Any]) -> tuple[int, str]:
        sev_id = _safe_int(payload.get("severity_id"))
        # Negative rank so higher severity sorts first.
        rank = -_SEVERITY_RANK.get(sev_id, 0)
        info = payload.get("finding_info") or {}
        return (rank, _safe_str(info.get("uid")))

    return tuple(sorted(raw, key=key)[:n])


def _first_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    evidences = payload.get("evidences") or []
    if isinstance(evidences, list) and evidences and isinstance(evidences[0], dict):
        return dict(evidences[0])
    return {}


def _safe_str(value: object) -> str:
    return str(value) if isinstance(value, str) else ""


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    return 0


def _safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


__all__ = ["build_context_bundle"]
