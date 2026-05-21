"""Tests — `meta_harness.reporter` (Task 9).

12 tests covering:

1.  Header carries customer_id + run_id + scan window.
2.  Empty scorecards renders the "no agents evaluated" placeholder.
3.  Single-agent scorecard row formatted correctly.
4.  Failed scorecard (pass_rate=None, error set) renders error cell.
5.  Regressions-flagged section omitted (empty) -> "no regressions".
6.  Regressions section formatted with Δ column.
7.  A/B section absent when ``report.ab_comparison is None``.
8.  A/B section renders byte_equal=True marker.
9.  A/B section renders per-case delta table when present.
10. Watch-list defaults to "no agents" with empty arg.
11. Watch-list renders the provided agents.
12. Footer carries the schema_version.
"""

from __future__ import annotations

from datetime import UTC, datetime

from meta_harness.reporter import render_report
from meta_harness.schemas import (
    ABComparison,
    ABComparisonCaseDelta,
    MetaHarnessReport,
    RegressionFlag,
    Scorecard,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def _report(
    *,
    scorecards: tuple[Scorecard, ...] = (),
    regressions: tuple[RegressionFlag, ...] = (),
    ab: ABComparison | None = None,
) -> MetaHarnessReport:
    return MetaHarnessReport(
        customer_id="acme",
        run_id="r1",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
        scorecards=scorecards,
        scorecard_deltas=(),
        regressions_flagged=regressions,
        ab_comparison=ab,
    )


def _success_scorecard(agent_id: str, pass_rate: float = 0.9) -> Scorecard:
    return Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id=agent_id,
        total_cases=10,
        passed=int(pass_rate * 10),
        failed=10 - int(pass_rate * 10),
        pass_rate=pass_rate,
        evaluated_at=_NOW,
    )


def _failed_scorecard(agent_id: str, error: str = "boom") -> Scorecard:
    return Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id=agent_id,
        total_cases=0,
        passed=0,
        failed=0,
        error=error,
        evaluated_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Header + footer
# ---------------------------------------------------------------------------


def test_header_carries_customer_run_and_window() -> None:
    out = render_report(_report())
    assert "`acme` / `r1`" in out
    assert "Scan window:" in out
    assert "2026-05-21" in out


def test_footer_carries_schema_version() -> None:
    out = render_report(_report())
    assert "meta_harness.v0.1" in out


# ---------------------------------------------------------------------------
# Batch eval summary
# ---------------------------------------------------------------------------


def test_empty_scorecards_placeholder() -> None:
    out = render_report(_report())
    assert "No agents evaluated this run" in out


def test_single_agent_scorecard_row_formatted() -> None:
    sc = _success_scorecard("cloud_posture", pass_rate=0.9)
    out = render_report(_report(scorecards=(sc,)))
    assert "| `cloud_posture` | 10 | 9 | 1 | 90.0% | — |" in out


def test_failed_scorecard_renders_error_cell() -> None:
    sc = _failed_scorecard("data_security", error="ImportError")
    out = render_report(_report(scorecards=(sc,)))
    assert "| `data_security` | 0 | 0 | 0 | — | ImportError |" in out


# ---------------------------------------------------------------------------
# Regressions
# ---------------------------------------------------------------------------


def test_empty_regressions_placeholder() -> None:
    out = render_report(_report())
    assert "No regressions detected" in out


def test_regressions_table_formatted() -> None:
    flag = RegressionFlag(
        agent_id="cloud_posture",
        previous_pass_rate=0.9,
        current_pass_rate=0.7,
        delta_pct=-20.0,
    )
    out = render_report(_report(regressions=(flag,)))
    assert "1 agent(s) crossed" in out
    assert "| `cloud_posture` | 90.0% | 70.0% | -20.0 pct |" in out


# ---------------------------------------------------------------------------
# A/B section
# ---------------------------------------------------------------------------


def test_ab_section_absent_when_none() -> None:
    out = render_report(_report())
    assert "## A/B comparison" not in out


def test_ab_section_byte_equal_marker() -> None:
    ab = ABComparison(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="/nlah/a",
        variant_b_path="/nlah/b",
        variant_a_pass_rate=0.9,
        variant_b_pass_rate=0.9,
        byte_equal=True,
        evaluated_at=_NOW,
    )
    out = render_report(_report(ab=ab))
    assert "## A/B comparison" in out
    assert "byte-equal" in out


def test_ab_section_per_case_delta_table() -> None:
    ab = ABComparison(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="/nlah/a",
        variant_b_path="/nlah/b",
        variant_a_pass_rate=1.0,
        variant_b_pass_rate=0.5,
        per_case_deltas=(
            ABComparisonCaseDelta(
                case_id="c1", variant_a_passed=True, variant_b_passed=False, byte_equal=False
            ),
            ABComparisonCaseDelta(
                case_id="c2", variant_a_passed=True, variant_b_passed=True, byte_equal=True
            ),
        ),
        byte_equal=False,
        evaluated_at=_NOW,
    )
    out = render_report(_report(ab=ab))
    assert "| `c1` | ✓ pass | ✗ fail | ✗ |" in out
    assert "| `c2` | ✓ pass | ✓ pass | ✓ |" in out


# ---------------------------------------------------------------------------
# Watch-list
# ---------------------------------------------------------------------------


def test_watch_list_default_placeholder() -> None:
    out = render_report(_report())
    assert "No agents trending down" in out


def test_watch_list_renders_provided_agents() -> None:
    out = render_report(_report(), watch_list_agents=("cloud_posture", "data_security"))
    assert "2 agent(s) trending down" in out
    assert "- `cloud_posture`" in out
    assert "- `data_security`" in out
