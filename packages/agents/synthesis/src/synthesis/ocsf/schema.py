"""OCSF 2004 Detection Finding for synthesis (synthesis v0.2 Task 2, Q1).

D.13's v0.1 emitted **markdown only** — OCSF emission was deferred pending a class_uid decision.
Q1 resolves it: synthesis emits **OCSF v1.3 Detection Finding (class_uid 2004)** — the same wire
shape as D.2/D.3/D.4/D.8 — with the **markdown narrative carried in the `unmapped` slot** (the
precedent F.6 set with its chain hashes). The markdown report + executive summary continue as
operator-readable artifacts (Q1/WI-Y12 — OCSF is additive, not a replacement).

Pure + deterministic: the same narrative input yields a byte-identical OCSF payload (WI-Y5).
"""

from __future__ import annotations

from typing import Any

OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2004  # Detection Finding
OCSF_CLASS_NAME = "Detection Finding"
OCSF_ACTIVITY_CREATE = 1
OCSF_STATUS_NEW = 1

#: OCSF severity_id: 1 Informational · 2 Low · 3 Medium · 4 High · 5 Critical.
_SEVERITY_TO_ID: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def severity_to_id(severity: str) -> int:
    """Map a severity label to its OCSF id (unknown -> Informational)."""
    return _SEVERITY_TO_ID.get(severity.lower(), 1)


def build_synthesis_finding(
    *,
    finding_id: str,
    title: str,
    narrative_markdown: str,
    executive_summary: str,
    severity: str,
    source_finding_ids: tuple[str, ...],
    detected_at_ms: int,
) -> dict[str, Any]:
    """Render a synthesized narrative as an OCSF 2004 Detection Finding. The narrative +
    executive summary + cited source finding ids ride in the ``unmapped`` slot."""
    return {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{OCSF_CLASS_NAME}: Create",
        "severity_id": severity_to_id(severity),
        "severity": severity.capitalize(),
        "time": detected_at_ms,
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Nexus Synthesis", "vendor_name": "Nexus Cyber OS"},
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "types": ["narrative_synthesis"],
        },
        "unmapped": {
            "narrative_markdown": narrative_markdown,
            "executive_summary": executive_summary,
            "source_finding_ids": sorted(source_finding_ids),
        },
    }
