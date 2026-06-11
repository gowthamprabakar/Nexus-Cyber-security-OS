"""D.2 Identity (OCSF 2004) consumption for data-access governance (data-security v0.2 Task 14).

Per **Q5** data-security reads D.2 Identity's OCSF 2004 findings to learn which resources
carry over-permissive access, then flags the **data + over-permissive-access** combination
(Task 15). This module is the consumption half: it pulls the affected-resource identifiers
(ARNs) out of a D.2 report and matches them to the unified data sources.

This is **advisory only** (WI-S11): data-security emits + maps; it never modifies IAM (A.1
Remediation owns enforcement). (The new module lives at the package top level because
``correlate`` is a single-file module, not a package.)
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from data_security.tools.data_source import DataSource


def extract_flagged_resources(identity_report: dict[str, Any]) -> set[str]:
    """The affected-resource identifiers (ARNs / names) from D.2's OCSF 2004 findings —
    each is a principal/resource D.2 flagged for an access issue."""
    out: set[str] = set()
    findings = identity_report.get("findings") if isinstance(identity_report, dict) else None
    if not isinstance(findings, list):
        return out
    for raw in findings:
        if not isinstance(raw, dict) or raw.get("class_uid") != 2004:
            continue
        resources = raw.get("resources")
        if not isinstance(resources, list):
            continue
        for res in resources:
            if not isinstance(res, dict):
                continue
            for key in ("uid", "name"):
                value = res.get(key)
                if isinstance(value, str) and value:
                    out.add(value)
    return out


def flagged_data_sources(
    sources: Sequence[DataSource], *, identity_report: dict[str, Any]
) -> set[str]:
    """The data-source identifiers that appear in a D.2-flagged resource (e.g. the bucket
    name inside an over-permissive role's resource ARN). Substring match — a v0.2 heuristic."""
    flagged = extract_flagged_resources(identity_report)
    haystack = "\n".join(flagged)
    return {s.identifier for s in sources if s.identifier and s.identifier in haystack}
