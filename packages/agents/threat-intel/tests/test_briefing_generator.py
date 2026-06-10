"""D.8 v0.2 Task 12 — briefing generator skeleton tests."""

from __future__ import annotations

import pytest
from threat_intel.briefing.generator import Briefing, TimeRange, generate_briefing

_TR = TimeRange(start="2026-06-01T00:00:00Z", end="2026-06-10T00:00:00Z")
_FINDINGS = [
    {"severity": "Critical", "title": "KEV match"},
    {"severity": "High", "title": "IOC match"},
    {"severity": "Critical", "title": "another KEV"},
]


def test_returns_briefing_with_counts() -> None:
    b = generate_briefing(_FINDINGS, customer_id="cust_test", time_range=_TR)
    assert isinstance(b, Briefing)
    assert b.finding_count == 3
    assert b.severity_counts == {"Critical": 2, "High": 1}
    assert b.customer_id == "cust_test" and b.time_range == _TR


def test_markdown_contains_header_window_and_breakdown() -> None:
    md = generate_briefing(_FINDINGS, customer_id="cust_test", time_range=_TR).markdown
    assert "# Threat Intelligence Briefing — cust_test" in md
    assert "2026-06-01T00:00:00Z → 2026-06-10T00:00:00Z" in md
    assert "**Total findings:** 3" in md
    assert "- **Critical**: 2" in md and "- **High**: 1" in md


def test_severity_breakdown_is_ordered_most_to_least_severe() -> None:
    md = generate_briefing(_FINDINGS, customer_id="c", time_range=_TR).markdown
    assert md.index("**Critical**") < md.index("**High**")


def test_empty_findings_valid_briefing() -> None:
    b = generate_briefing([], customer_id="c", time_range=_TR)
    assert b.finding_count == 0 and b.severity_counts == {}
    assert "_No findings in this window._" in b.markdown


def test_missing_severity_defaults_to_unknown() -> None:
    b = generate_briefing([{"title": "x"}], customer_id="c", time_range=_TR)
    assert b.severity_counts == {"Unknown": 1}


def test_v0_3_placeholders_present() -> None:
    md = generate_briefing(_FINDINGS, customer_id="c", time_range=_TR).markdown
    assert "## Key threats" in md and "## Recommendations" in md


def test_unsupported_format_raises() -> None:
    with pytest.raises(ValueError, match="unsupported briefing format"):
        generate_briefing(_FINDINGS, customer_id="c", time_range=_TR, fmt="pdf")
