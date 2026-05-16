"""`render_summary` — operator-facing markdown report.

Mirrors the dual-pin pattern from F.3 / D.3 / D.4 / D.5 / D.6:

1. **Pinned at the top: rollbacks** — every `executed_rolled_back` action gets
   surface attention BEFORE the per-outcome rollup. A rollback means the
   agent's patch didn't fix the issue; operators need to investigate.
2. **Pinned second: failures** — `dry_run_failed` + `execute_failed` actions.
   The patch path is broken (admission webhook, syntax error, RBAC denied).

After the two pinned sections, a per-outcome breakdown and a per-action-class
breakdown give the operator the full picture. Audit chain head/tail hashes
are pinned at the bottom so operators can verify the chain end-to-end.

The renderer is **pure** (no I/O) — takes a `RemediationReport` and returns
markdown text. The driver writes the result to `report.md` in the workspace.
"""

from __future__ import annotations

from typing import Any

from remediation.schemas import (
    RemediationActionType,
    RemediationOutcome,
    RemediationReport,
)

# Outcome ordering for the per-outcome table — most-actionable first.
_OUTCOME_ORDER: tuple[RemediationOutcome, ...] = (
    RemediationOutcome.EXECUTED_ROLLED_BACK,
    RemediationOutcome.EXECUTE_FAILED,
    RemediationOutcome.DRY_RUN_FAILED,
    RemediationOutcome.REFUSED_UNAUTHORIZED,
    RemediationOutcome.REFUSED_BLAST_RADIUS,
    RemediationOutcome.EXECUTED_VALIDATED,
    RemediationOutcome.DRY_RUN_ONLY,
    RemediationOutcome.RECOMMENDED_ONLY,
)


def render_summary(
    report: RemediationReport,
    *,
    audit_head_hash: str | None = None,
    audit_tail_hash: str | None = None,
) -> str:
    """Render a `RemediationReport` to operator-facing markdown.

    Args:
        report: The run's `RemediationReport` (one OCSF 2007 record per attempt).
        audit_head_hash: Optional genesis or first-entry hash of the run's audit
            chain. Included in the report footer so operators can verify the chain
            end-to-end.
        audit_tail_hash: Optional last-entry hash of the audit chain (same purpose).

    Returns:
        A markdown string. The driver writes it to `report.md` in the workspace.
    """
    lines: list[str] = []

    # Header.
    lines.append("# Remediation Report")
    lines.append("")
    lines.append(f"- Customer: `{report.customer_id}`")
    lines.append(f"- Run ID: `{report.run_id}`")
    lines.append(f"- Mode: **{report.mode.value}**")
    lines.append(f"- Total attempted actions: **{report.total}**")
    lines.append("")

    outcome_counts = report.count_by_outcome()
    rolled_back = _findings_with_outcome(report, RemediationOutcome.EXECUTED_ROLLED_BACK)
    failed = _findings_with_outcome(
        report, RemediationOutcome.EXECUTE_FAILED
    ) + _findings_with_outcome(report, RemediationOutcome.DRY_RUN_FAILED)

    # Pin 1: rollbacks.
    if rolled_back:
        lines.append(f"## Pinned: rollbacks ({len(rolled_back)})")
        lines.append("")
        lines.append(
            "These actions applied but were reverted by post-validation. "
            "The detector re-ran after the rollback window and still saw the "
            "source rule_id — A.1 reversed the patch. Investigate the workload."
        )
        lines.append("")
        for entry in rolled_back:
            lines.extend(_format_action_bullet(entry))
        lines.append("")

    # Pin 2: failures (dry-run + execute hard fails).
    if failed:
        lines.append(f"## Pinned: failures ({len(failed)})")
        lines.append("")
        lines.append(
            "kubectl returned non-zero on these actions — most often an admission "
            "webhook rejection, a schema violation, or an RBAC denial. The "
            "audit chain has the full `stderr_head` for each. No state changed."
        )
        lines.append("")
        for entry in failed:
            lines.extend(_format_action_bullet(entry))
        lines.append("")

    # Per-outcome breakdown.
    lines.append("## Per-outcome breakdown")
    lines.append("")
    for outcome in _OUTCOME_ORDER:
        count = outcome_counts.get(outcome.value, 0)
        if count == 0:
            continue
        lines.append(f"- **{outcome.value}**: {count}")
    lines.append("")

    # Per-action-class breakdown.
    by_action = _group_by_action(report)
    if by_action:
        lines.append("## Per-action-class breakdown")
        lines.append("")
        for action_value in sorted(by_action):
            entries = by_action[action_value]
            lines.append(f"- **{action_value}**: {len(entries)}")
        lines.append("")

    # All actions (one bullet each, grouped under their outcome).
    lines.append("## All actions")
    lines.append("")
    for outcome in _OUTCOME_ORDER:
        entries = _findings_with_outcome(report, outcome)
        if not entries:
            continue
        lines.append(f"### {outcome.value} ({len(entries)})")
        lines.append("")
        for entry in entries:
            lines.extend(_format_action_bullet(entry))
        lines.append("")

    # Audit chain footer.
    if audit_head_hash or audit_tail_hash:
        lines.append("## Audit chain")
        lines.append("")
        if audit_head_hash:
            lines.append(f"- Head hash: `{audit_head_hash}`")
        if audit_tail_hash:
            lines.append(f"- Tail hash: `{audit_tail_hash}`")
        lines.append("")
        lines.append(
            "Verify with `audit-agent query --source <workspace>/audit.jsonl` "
            "(F.6's 5-axis query API)."
        )

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------- helpers -------------------------------------


def _findings_with_outcome(
    report: RemediationReport,
    outcome: RemediationOutcome,
) -> list[dict[str, Any]]:
    """Return the raw OCSF 2007 dicts whose `analytic.name` matches the given outcome.

    Order is preserved from the report (which preserves agent execution order).
    """
    out: list[dict[str, Any]] = []
    for raw in report.findings:
        try:
            if raw["finding_info"]["analytic"]["name"] == outcome.value:
                out.append(raw)
        except (KeyError, TypeError):
            continue
    return out


def _group_by_action(report: RemediationReport) -> dict[str, list[dict[str, Any]]]:
    """Group findings by `finding_info.types[0]` (the action type discriminator)."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for raw in report.findings:
        try:
            action_value = raw["finding_info"]["types"][0]
        except (KeyError, TypeError, IndexError):
            continue
        if not isinstance(action_value, str):
            continue
        try:
            RemediationActionType(action_value)  # validate
        except ValueError:
            continue
        grouped.setdefault(action_value, []).append(raw)
    return grouped


def _format_action_bullet(entry: dict[str, Any]) -> list[str]:
    """Format one OCSF 2007 record as a markdown bullet block.

    Pulls the artifact handle from `evidences[]` (every record has a
    `remediation-artifact` evidence entry when the action_class built one).
    """
    finding_info = entry.get("finding_info") or {}
    uid = finding_info.get("uid", "<no-uid>")
    title = finding_info.get("title", "")

    artifact_ev = _find_artifact_evidence(entry)
    target = artifact_ev.get("target") if artifact_ev else None
    action_type = artifact_ev.get("action_type") if artifact_ev else "?"
    correlation_id = artifact_ev.get("correlation_id") if artifact_ev else "?"

    if isinstance(target, dict):
        location = (
            f"{target.get('namespace', '?')}/{target.get('kind', '?')}/{target.get('name', '?')}"
        )
    else:
        location = "?"

    return [
        f"- `{uid}` — {title}",
        f"  - action_type: `{action_type}`",
        f"  - location: `{location}`",
        f"  - correlation_id: `{correlation_id}`",
    ]


def _find_artifact_evidence(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Return the entry's `remediation-artifact` evidence, or None if absent."""
    evidences = entry.get("evidences") or []
    if not isinstance(evidences, list):
        return None
    for ev in evidences:
        if isinstance(ev, dict) and ev.get("kind") == "remediation-artifact":
            return ev
    return None


__all__ = ["render_summary"]
