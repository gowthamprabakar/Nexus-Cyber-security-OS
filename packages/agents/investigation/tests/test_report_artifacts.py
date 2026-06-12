"""investigation v0.2 Task 13 — report artifact tests (WI-I17/WI-I5)."""

from __future__ import annotations

from investigation.report.artifacts import attach_cost_section, render_plan_md


def _bundle() -> dict:
    return {
        "advisory": True,
        "enforced": False,
        "recommendations": [
            {
                "action_type": "rotate_credentials",
                "target": "key-1",
                "severity": "critical",
                "rationale": "exposed",
            },
        ],
    }


def test_render_plan_md_has_advisory_note() -> None:
    md = render_plan_md(_bundle())
    assert md.startswith("# Containment Plan (advisory)")
    assert "advisory" in md and "rotate_credentials" in md and "key-1" in md


def test_render_plan_md_empty() -> None:
    md = render_plan_md({"recommendations": []})
    assert "No containment recommendations" in md


def test_attach_cost_section() -> None:
    report = {"class_uid": 2005, "finding_info": {"uid": "INC-1"}}
    out = attach_cost_section(
        report, {"llm_call_count": 3, "estimated_tokens": 900, "provider_used": "deepseek"}
    )
    assert out["llm_cost"]["llm_call_count"] == 3
    assert out["class_uid"] == 2005  # OCSF envelope untouched (WI-I5)


def test_attach_cost_does_not_mutate_original() -> None:
    report = {"class_uid": 2005}
    attach_cost_section(report, {"llm_call_count": 1})
    assert "llm_cost" not in report  # original untouched


def test_render_plan_md_numbered() -> None:
    bundle = {
        "recommendations": [
            {
                "action_type": "rotate_credentials",
                "target": "k",
                "severity": "critical",
                "rationale": "a",
            },
            {"action_type": "isolate_host", "target": "h", "severity": "high", "rationale": "b"},
        ]
    }
    md = render_plan_md(bundle)
    assert "1. **rotate_credentials**" in md and "2. **isolate_host**" in md
