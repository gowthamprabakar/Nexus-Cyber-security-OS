"""Multi-emitter OCSF 2003 consumption (compliance v0.2 Tasks 9-11).

Reads sibling-agent OCSF 2003 findings reports (F.3 / D.5 / k8s-posture) and extracts, for
a given source agent, the **(evaluated, failing)** rule-id sets the roll-up + PASS
attestation need (WI-C2). Each source finding is a *violation*, so its rule id is a
**failing** rule. "Evaluated" rules = the rules compliance maps for that agent (its universe
of interest), conditioned on the agent having run — an honest v0.2 proxy (per-resource
evaluation evidence is deferred; documented in §5).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from compliance.rollup import FrameworkRollup, roll_up_framework
from compliance.tools.cis_aws_benchmark import CisControl


def extract_failing_rule_ids(report: dict[str, Any]) -> set[str]:
    """The rule ids of every OCSF 2003 finding in a report — each is a failing rule. Reads
    ``compliance.control`` (where sibling agents place the source rule id)."""
    out: set[str] = set()
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        return out
    for raw in findings:
        if not isinstance(raw, dict) or raw.get("class_uid") != 2003:
            continue
        compliance = raw.get("compliance")
        if isinstance(compliance, dict):
            rid = compliance.get("control")
            if isinstance(rid, str) and rid:
                out.add(rid)
    return out


def mapped_rules_for_agent(controls: Sequence[CisControl], *, source_agent: str) -> set[str]:
    """The set of source rule ids the control library maps for ``source_agent``."""
    out: set[str] = set()
    for control in controls:
        for m in control.source_mappings:
            if m.source_agent == source_agent:
                out.add(m.source_rule_id)
    return out


def agent_ran(report: dict[str, Any]) -> bool:
    """A report counts as 'agent ran' when it carries a findings list (even if empty)."""
    return isinstance(report, dict) and isinstance(report.get("findings"), list)


def source_evaluation(
    report: dict[str, Any], controls: Sequence[CisControl], *, source_agent: str
) -> tuple[set[str], set[str]]:
    """Return ``(evaluated, failing)`` rule-id sets for ``source_agent``: failing = the
    agent's emitted (violation) rules intersected with compliance's mapped universe;
    evaluated = that mapped universe iff the agent ran (else empty)."""
    mapped = mapped_rules_for_agent(controls, source_agent=source_agent)
    failing = extract_failing_rule_ids(report) & mapped
    evaluated = mapped if agent_ran(report) else set()
    return evaluated, failing


def evaluate_framework(
    framework: str,
    report: dict[str, Any],
    controls: Sequence[CisControl],
    *,
    source_agent: str,
) -> FrameworkRollup:
    """End-to-end: consume one source agent's report + roll the framework up to a
    PASS/FAIL/not-evaluated summary (ties Task 8 roll-up to Task 9 consumption)."""
    evaluated, failing = source_evaluation(report, controls, source_agent=source_agent)
    pairs: list[tuple[str, list[str]]] = [
        (
            c.control_id,
            [m.source_rule_id for m in c.source_mappings if m.source_agent == source_agent],
        )
        for c in controls
    ]
    return roll_up_framework(framework, pairs, evaluated=evaluated, failing=failing)
