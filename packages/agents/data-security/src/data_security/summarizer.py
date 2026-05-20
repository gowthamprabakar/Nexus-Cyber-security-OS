"""Summarizer — Stage 6 (SUMMARIZE) of the D.5 7-stage pipeline.

Deterministic markdown render of D.5 findings. Pure function:
``render_summary(findings, *, run_id) -> str``.

Layout (mirrors F.3 / D.4 / multi-cloud-posture / k8s-posture):

1. **Header** — agent identifier, run-id, finding totals per severity.
2. **Per-detector breakdown** — count of findings per detector rule.
3. **CRITICAL** section — every CRITICAL finding spelled out.
4. **HIGH** section.
5. **MEDIUM** section.
6. **LOW + INFO** sections (collapsed when empty).

The CRITICAL section is **pinned above** the rest, matching F.3
operator-friendly precedent.

Q6 PRIVACY-CONTRACT RENDER-LAYER ASSERT (LOAD-BEARING).
========================================================

After rendering, the summarizer runs the classifier (Task 3) over
the full output. If the classifier returns any label other than
``ClassifierLabel.NONE`` — meaning the rendered text contains a PII
pattern — that's a Q6 violation and ``SummarizerQ6Violation`` is
raised. This is a regression guard: if a future change accidentally
adds matched-content to a finding's evidence dict and the renderer
prints it, the violation surfaces immediately rather than silently
leaking in production.

The renderer itself prints ONLY label tokens (e.g. ``"ssn"``,
``"credit_card"``), never matched text. The Q6 assert is the
backstop.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from data_security.classifiers import classify
from data_security.schemas import (
    ClassifierLabel,
    CloudPostureFinding,
    Severity,
)

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_AGENT_TITLE = "Data Security Agent (D.5) — Run Report"


class SummarizerQ6Violation(RuntimeError):
    """The Q6 privacy-contract render-layer assert tripped.

    Raised by ``render_summary`` when the classifier finds a PII
    pattern in the rendered markdown output. Operator MUST treat this
    as a P0 bug — review the latest detector / scorer / evidence
    changes for leaks of matched-text into evidence dicts.
    """


def render_summary(
    findings: Iterable[CloudPostureFinding],
    *,
    run_id: str,
) -> str:
    """Render the markdown summary report.

    Pure function: no I/O, no module state. Deterministic for the
    same input. Q6 render-layer assert runs on the output; raises
    ``SummarizerQ6Violation`` if any PII pattern leaked.
    """
    findings_list = list(findings)
    findings_by_severity = _bucket_by_severity(findings_list)
    findings_by_rule = _bucket_by_rule(findings_list)

    sections: list[str] = [
        _render_header(run_id, findings_by_severity, total=len(findings_list)),
        _render_per_detector_breakdown(findings_by_rule),
    ]
    for sev in _SEVERITY_ORDER:
        section = _render_severity_section(sev, findings_by_severity.get(sev, []))
        if section:
            sections.append(section)

    if not findings_list:
        sections.append("## Findings\n\nNo findings emitted. ✅")

    rendered = "\n\n".join(sections) + "\n"

    # Q6 render-layer assert — LOAD-BEARING.
    _assert_no_pii_leak(rendered)

    return rendered


# ---------------------------------------------------------------------------
# Q6 render-layer assert
# ---------------------------------------------------------------------------


def _assert_no_pii_leak(rendered: str) -> None:
    """Run the classifier (Task 3) over the rendered text.

    The renderer prints only label tokens (``"ssn"``, ``"credit_card"``,
    etc.), severity strings, rule_ids, bucket names, ARNs, and
    finding-ids. None of those should match a classifier regex
    pattern. If any do, that's a Q6 violation — a previous-stage
    change must have leaked matched content into evidence.
    """
    label = classify(rendered)
    if label != ClassifierLabel.NONE:
        raise SummarizerQ6Violation(
            f"Q6 privacy-contract violation: classifier found {label.value!r} pattern in "
            f"rendered report. The renderer must not include classifier-matched content. "
            f"Review the latest evidence-dict additions for matched-text leaks."
        )


# ---------------------------------------------------------------------------
# section renderers
# ---------------------------------------------------------------------------


def _render_header(
    run_id: str,
    findings_by_severity: dict[Severity, list[CloudPostureFinding]],
    *,
    total: int,
) -> str:
    lines: list[str] = [
        f"# {_AGENT_TITLE}",
        "",
        f"**run_id**: `{run_id}`",
        f"**total_findings**: {total}",
        "",
        "**Severity breakdown**:",
        "",
    ]
    for sev in _SEVERITY_ORDER:
        count = len(findings_by_severity.get(sev, []))
        lines.append(f"- **{sev.value.upper()}**: {count}")
    return "\n".join(lines)


def _render_per_detector_breakdown(
    findings_by_rule: dict[str, list[CloudPostureFinding]],
) -> str:
    if not findings_by_rule:
        return "## Detector breakdown\n\n_No findings._"
    lines: list[str] = ["## Detector breakdown", ""]
    for rule in sorted(findings_by_rule.keys()):
        count = len(findings_by_rule[rule])
        lines.append(f"- `{rule}`: {count}")
    return "\n".join(lines)


def _render_severity_section(
    sev: Severity,
    findings: list[CloudPostureFinding],
) -> str:
    if not findings:
        return ""
    lines: list[str] = [f"## {sev.value.upper()} ({len(findings)})", ""]
    # Stable order: by finding_id for determinism.
    for f in sorted(findings, key=lambda x: x.finding_id):
        lines.append(_render_finding_block(f))
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_finding_block(f: CloudPostureFinding) -> str:
    payload = f.to_dict()
    arns = _safe_arns(payload)
    arn_lines = "\n".join(f"  - `{a}`" for a in arns) if arns else "  - (no resource ARN recorded)"
    labels = _safe_classifier_labels(payload)
    label_line = (
        f"- **classifier labels**: {', '.join(f'`{lbl}`' for lbl in labels)}"
        if labels
        else "- **classifier labels**: (none)"
    )
    correlation_ids = _safe_correlation_ids(payload)
    if correlation_ids:
        correlation_line = (
            "- **F.3 correlation**: "
            + ", ".join(f"`{cid}`" for cid in correlation_ids)
            + " (severity uplifted)"
        )
    else:
        correlation_line = ""

    parts = [
        f"### `{f.finding_id}` — {payload.get('finding_info', {}).get('title', '(no title)')}",
        f"- **rule**: `{f.rule_id}`",
        f"- **severity**: `{f.severity.value}`",
        "- **affected resources**:",
        arn_lines,
        label_line,
    ]
    if correlation_line:
        parts.append(correlation_line)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _bucket_by_severity(
    findings: Iterable[CloudPostureFinding],
) -> dict[Severity, list[CloudPostureFinding]]:
    out: dict[Severity, list[CloudPostureFinding]] = {}
    for f in findings:
        out.setdefault(f.severity, []).append(f)
    return out


def _bucket_by_rule(
    findings: Iterable[CloudPostureFinding],
) -> dict[str, list[CloudPostureFinding]]:
    out: dict[str, list[CloudPostureFinding]] = {}
    for f in findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


def _safe_arns(payload: dict[str, Any]) -> list[str]:
    resources = payload.get("resources", [])
    if not isinstance(resources, list):
        return []
    arns: list[str] = []
    for r in resources:
        if isinstance(r, dict):
            uid = r.get("uid")
            if isinstance(uid, str) and uid:
                arns.append(uid)
    return arns


def _safe_classifier_labels(payload: dict[str, Any]) -> list[str]:
    """Extract sorted classifier labels from the detector evidence.

    Returns ONLY label tokens (e.g. ``"ssn"``, ``"credit_card"``) —
    never the matched substring. The detector and scorer evidence
    structures are the source of truth; this helper just surfaces
    the labels in the report.
    """
    evidences = payload.get("evidences", [])
    if not isinstance(evidences, list):
        return []
    labels: set[str] = set()
    for ev in evidences:
        if not isinstance(ev, dict):
            continue
        raw = ev.get("classifier_labels_found", [])
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    labels.add(item)
    return sorted(labels)


def _safe_correlation_ids(payload: dict[str, Any]) -> list[str]:
    """Extract F.3 correlation finding-ids from the scorer's uplift evidence."""
    evidences = payload.get("evidences", [])
    if not isinstance(evidences, list):
        return []
    ids: list[str] = []
    for ev in evidences:
        if not isinstance(ev, dict):
            continue
        if ev.get("rule") != "correlation_uplift":
            continue
        raw = ev.get("matched_f3_finding_ids", [])
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    ids.append(item)
    return ids
