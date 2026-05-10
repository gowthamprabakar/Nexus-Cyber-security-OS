"""Markdown renderers — auditor-readable reports for suite, comparison, gate.

Per F.2 plan Task 10. Reports lead with the most important number so an SRE
can scan in 30 seconds: pass ratio for suites, regression count for
comparisons, pass / fail verdict for gates. Per-case detail follows in
tables.

Renderers always return `str` and never raise on valid pydantic input —
malformed values (long failure reasons, missing optional fields) are
tolerated and rendered, never traced.
"""

from __future__ import annotations

from typing import Any

from eval_framework.compare import CaseDiff, ComparisonReport
from eval_framework.gate import GateResult
from eval_framework.results import EvalResult, SuiteResult

# ---------------------------- helpers ------------------------------------


def _total_tokens(result: EvalResult) -> int:
    return sum(c.input_tokens + c.output_tokens for c in result.trace.llm_calls)


def _safe_cell(text: str | None) -> str:
    """Make a string safe for a markdown table cell."""
    if text is None:
        return "—"
    # Collapse whitespace and escape pipes so the table doesn't shear.
    return text.replace("\n", " ").replace("|", "\\|").strip() or "—"


def _truncate(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _kv_block(label: str, value: str | None) -> str:
    return f"- **{label}:** {value if value else '—'}"


# ---------------------------- Suite report -------------------------------


def render_suite_md(suite: SuiteResult) -> str:
    """Render a SuiteResult as a markdown report.

    Layout:
    1. Header + suite metadata block (provider, model_pin, ci labels).
    2. Headline pass ratio + duration.
    3. Per-severity rollup if any case has `actuals.by_severity`.
    4. Per-case table (case_id, status, duration, tokens, failure reason).
    """
    total = suite.total
    passed = suite.passed
    pct = 100.0 * suite.pass_rate

    lines: list[str] = []
    lines.append(f"# Eval suite — {suite.suite_id}")
    lines.append("")

    # Metadata block.
    lines.append(_kv_block("Runner", suite.runner))
    lines.append(_kv_block("Suite ID", suite.suite_id))
    lines.append(_kv_block("Provider", suite.provider_id))
    lines.append(_kv_block("Model pin", suite.model_pin))
    lines.append(_kv_block("Started", suite.started_at.isoformat()))
    lines.append(_kv_block("Completed", suite.completed_at.isoformat()))
    duration = (suite.completed_at - suite.started_at).total_seconds()
    lines.append(_kv_block("Duration", f"{duration:.2f}s"))

    # Custom metadata appended one line each.
    for key, value in (suite.metadata or {}).items():
        lines.append(_kv_block(str(key), str(value)))

    lines.append("")

    # Headline.
    if total == 0:
        lines.append("**Result:** 0/0 cases — no cases in suite.")
        lines.append("")
        return "\n".join(lines)

    icon = "✅" if passed == total else "❌"
    lines.append(f"## {icon} {passed}/{total} passed ({pct:.1f}%)")
    lines.append("")

    # Per-severity rollup, if any case emits by_severity.
    severity_totals: dict[str, int] = {}
    for case in suite.cases:
        sev_map = case.actuals.get("by_severity") if isinstance(case.actuals, dict) else None
        if isinstance(sev_map, dict):
            for sev, count in sev_map.items():
                severity_totals[str(sev)] = severity_totals.get(str(sev), 0) + int(count)

    if severity_totals:
        lines.append("### Severity rollup")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("| -------- | ----: |")
        for sev in sorted(severity_totals.keys()):
            lines.append(f"| {sev} | {severity_totals[sev]} |")
        lines.append("")

    # Per-case table.
    lines.append("### Cases")
    lines.append("")
    lines.append("| Case | Status | Duration (s) | Tokens | Failure reason |")
    lines.append("| ---- | :----: | -----------: | -----: | -------------- |")
    for case in suite.cases:
        status = "✅ pass" if case.passed else "❌ fail"
        tokens = _total_tokens(case)
        token_cell = str(tokens) if tokens else "—"
        reason = _safe_cell(_truncate(case.failure_reason or ""))
        lines.append(
            f"| `{case.case_id}` | {status} | {case.duration_sec:.2f} | {token_cell} | {reason} |"
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------- Comparison report --------------------------


def _diff_status_icon(status: str) -> str:
    return {
        "unchanged_pass": "✅",
        "unchanged_fail": "⚠️",
        "newly_failing": "❌",
        "newly_passing": "🟢",
        "dropped": "[-]",
        "added": "[+]",
    }.get(status, "•")


def render_comparison_md(report: ComparisonReport) -> str:
    """Render a ComparisonReport as a markdown report.

    Leads with the regression count and pass-rate delta so a CI log can
    answer "did the candidate regress?" in the first line.
    """
    summary = report.summary

    lines: list[str] = []
    lines.append(f"# Eval comparison — {report.baseline_suite_id} → {report.candidate_suite_id}")
    lines.append("")

    # Headline diff line.
    delta_pct = summary.pass_rate_delta * 100.0
    sign = "+" if delta_pct > 0 else ""
    lines.append(
        f"**{summary.regressions_count} regression(s), "
        f"{summary.improvements_count} improvement(s); "
        f"pass-rate delta {sign}{delta_pct:.1f}%** "
        f"across {summary.total_cases} case(s)."
    )
    lines.append("")

    # Provider context.
    lines.append(_kv_block("Baseline suite", report.baseline_suite_id))
    lines.append(_kv_block("Baseline provider", report.baseline_provider_id))
    lines.append(_kv_block("Candidate suite", report.candidate_suite_id))
    lines.append(_kv_block("Candidate provider", report.candidate_provider_id))
    lines.append("")

    # Per-case diff table.
    lines.append("### Per-case diff")
    lines.append("")
    lines.append(
        "| Case | Status | Baseline | Candidate | Δ duration (s) | Δ tokens | Actuals changed |"
    )
    lines.append(
        "| ---- | :----: | :------: | :-------: | -------------: | -------: | :-------------: |"
    )
    for diff in report.case_diffs:
        token_delta_cell = "—" if diff.token_delta is None else f"{diff.token_delta:+d}"
        actuals_cell = "yes" if diff.actuals_changed else "no"
        lines.append(
            f"| `{diff.case_id}` "
            f"| {_diff_status_icon(diff.status)} {diff.status} "
            f"| {_passfail(diff.baseline_passed)} "
            f"| {_passfail(diff.candidate_passed)} "
            f"| {diff.duration_delta_sec:+.2f} "
            f"| {token_delta_cell} "
            f"| {actuals_cell} |"
        )

    lines.append("")
    return "\n".join(lines)


def _passfail(value: bool) -> str:
    return "pass" if value else "fail"


# ---------------------------- Gate report --------------------------------


def render_gate_md(gate_result: GateResult, suite: SuiteResult) -> str:
    """Render a GateResult against a SuiteResult."""
    icon = "✅" if gate_result.passed else "❌"
    verdict = "passed" if gate_result.passed else "failed"

    lines: list[str] = []
    lines.append(f"# Gate {verdict} {icon}")
    lines.append("")
    lines.append(_kv_block("Suite", suite.suite_id))
    lines.append(_kv_block("Runner", suite.runner))
    lines.append(_kv_block("Cases", f"{suite.passed}/{suite.total}"))
    lines.append(_kv_block("Pass rate", f"{suite.pass_rate * 100:.1f}%"))
    lines.append("")

    if gate_result.failures:
        lines.append("### Failures")
        lines.append("")
        for failure in gate_result.failures:
            lines.append(f"- ❌ {failure}")
        lines.append("")
    else:
        lines.append("All gate thresholds satisfied.")
        lines.append("")

    return "\n".join(lines)


# ---------------------------- Public surface ------------------------------

__all__ = [
    "render_comparison_md",
    "render_gate_md",
    "render_suite_md",
]


# Silence unused-import warnings for re-exported types in user code.
_ = (CaseDiff, Any)
