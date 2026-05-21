"""Markdown renderer — Stage 5 REPORT helper.

Pure-function renderer that builds the operator-facing
``meta_harness_report.md`` from a ``MetaHarnessReport``. Stage 6
HANDOFF (Task 10's driver) writes the returned string to the
workspace + the SemanticStore entities; this module just composes
the markdown.

**Sections (in render order):**

1. Header — customer / run / wall-clock window.
2. Batch eval summary table (per-agent scorecard row).
3. Regression flags section (≥5% pass-rate drop) or
   "No regressions detected".
4. A/B comparison section (conditional on
   ``report.ab_comparison`` being present).
5. Watch-list section (driver-supplied agents trending down;
   v0.1 ships the rendering surface even though the driver
   defaults to an empty list pending ≥2-prior-run history).
6. Schema-version footer.

**Read-only / pure.** No I/O; takes pydantic, returns ``str``.
"""

from __future__ import annotations

from collections.abc import Sequence

from meta_harness.schemas import (
    ABComparison,
    MetaHarnessReport,
    RegressionFlag,
    Scorecard,
)


def render_report(
    report: MetaHarnessReport,
    *,
    watch_list_agents: Sequence[str] = (),
) -> str:
    """Render a MetaHarnessReport to operator-facing markdown.

    Args:
        report: The assembled run artefact from Stage 5 REPORT.
        watch_list_agents: Optional list of agents the driver has
            classified as "trending down" across ≥2 prior runs.
            v0.1's driver typically passes an empty sequence
            (multi-run trending lives behind the same KG-history
            fetch that v0.2 will introduce).

    Returns:
        A markdown string suitable for writing as
        ``meta_harness_report.md``.
    """
    parts: list[str] = []
    parts.append(_render_header(report))
    parts.append(_render_scorecard_table(report.scorecards))
    parts.append(_render_regressions(report.regressions_flagged))
    if report.ab_comparison is not None:
        parts.append(_render_ab_comparison(report.ab_comparison))
    parts.append(_render_watch_list(watch_list_agents))
    parts.append(_render_footer(report))
    return "\n\n".join(parts) + "\n"


def _render_header(report: MetaHarnessReport) -> str:
    return (
        f"# Meta-Harness Report — `{report.customer_id}` / `{report.run_id}`\n\n"
        f"- **Scan window:** {report.scan_started_at.isoformat()} → "
        f"{report.scan_completed_at.isoformat()}\n"
        f"- **Agents evaluated:** {report.total_agents_evaluated} "
        f"({report.successful_runs} successful, "
        f"{report.total_agents_evaluated - report.successful_runs} errored)\n"
        f"- **Regressions flagged:** {report.total_regressions}"
    )


def _render_scorecard_table(scorecards: Sequence[Scorecard]) -> str:
    if not scorecards:
        return "## Batch eval summary\n\n_No agents evaluated this run._"

    lines: list[str] = [
        "## Batch eval summary",
        "",
        "| Agent | Total cases | Passed | Failed | Pass rate | Error |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for sc in scorecards:
        pass_rate_cell = _format_pass_rate(sc.pass_rate)
        error_cell = sc.error if sc.error else "—"
        lines.append(
            f"| `{sc.agent_id}` | {sc.total_cases} | {sc.passed} | "
            f"{sc.failed} | {pass_rate_cell} | {error_cell} |"
        )
    return "\n".join(lines)


def _render_regressions(flags: Sequence[RegressionFlag]) -> str:
    if not flags:
        return "## Regressions flagged\n\n_No regressions detected._"

    lines: list[str] = [
        "## Regressions flagged",
        "",
        f"_{len(flags)} agent(s) crossed the ≥5% pass-rate-drop threshold._",
        "",
        "| Agent | Previous | Current | Δ |",
        "| --- | --- | --- | --- |",
    ]
    for f in flags:
        lines.append(
            f"| `{f.agent_id}` | {_format_pass_rate(f.previous_pass_rate)} | "
            f"{_format_pass_rate(f.current_pass_rate)} | "
            f"{f.delta_pct:+.1f} pct |"
        )
    return "\n".join(lines)


def _render_ab_comparison(ab: ABComparison) -> str:
    byte_equal_label = "✓ byte-equal" if ab.byte_equal else "✗ divergent"
    lines: list[str] = [
        "## A/B comparison",
        "",
        f"- **Agent:** `{ab.agent_id}`",
        f"- **Variant A:** `{ab.variant_a_path}` — pass rate "
        f"{_format_pass_rate(ab.variant_a_pass_rate)}",
        f"- **Variant B:** `{ab.variant_b_path}` — pass rate "
        f"{_format_pass_rate(ab.variant_b_pass_rate)}",
        f"- **Byte-equal across variants (WI-3):** {byte_equal_label}",
    ]
    if ab.per_case_deltas:
        lines.append("")
        lines.append("| Case | Variant A | Variant B | Byte-equal |")
        lines.append("| --- | --- | --- | --- |")
        for d in ab.per_case_deltas:
            lines.append(
                f"| `{d.case_id}` | {_pass_marker(d.variant_a_passed)} | "
                f"{_pass_marker(d.variant_b_passed)} | "
                f"{'✓' if d.byte_equal else '✗'} |"
            )
    return "\n".join(lines)


def _render_watch_list(agents: Sequence[str]) -> str:
    if not agents:
        return "## Watch-list\n\n_No agents trending down across prior runs._"

    lines: list[str] = [
        "## Watch-list",
        "",
        f"_{len(agents)} agent(s) trending down across ≥2 prior runs:_",
        "",
    ]
    for agent_id in agents:
        lines.append(f"- `{agent_id}`")
    return "\n".join(lines)


def _render_footer(report: MetaHarnessReport) -> str:
    return f"---\n\n_Report schema: `{report.schema_version}`._"


def _format_pass_rate(rate: float | None) -> str:
    if rate is None:
        return "—"
    return f"{rate * 100:.1f}%"


def _pass_marker(passed: bool) -> str:
    return "✓ pass" if passed else "✗ fail"


__all__ = ["render_report"]
