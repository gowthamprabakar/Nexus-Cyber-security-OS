"""OCSF 2004 Detection Finding for curiosity (curiosity v0.2 Task 2, Q1).

D.12's v0.1 emitted **a ``claims.>`` CuriosityClaim envelope only** — OCSF emission was deferred
pending a class_uid decision. Q1 resolves it: D.12 emits **OCSF v1.3 Detection Finding (class_uid
2004)** — the same wire shape as D.2/D.3/D.4/D.8/D.13 — with the **CuriosityClaim carried in the
``unmapped`` slot** (the precedent D.13 set with its narrative). The CuriosityClaim envelope on
``claims.>`` + the workspace markdown CONTINUE unchanged (Q1/WI-X6 — OCSF is additive, not a
replacement). D.12 becomes the **6th OCSF 2004 emitter**.

Pure + deterministic: the same claim input yields a byte-identical OCSF payload (WI-X5).
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


def build_curiosity_finding(
    *,
    claim_id: str,
    title: str,
    statement: str,
    rationale: str,
    severity: str,
    coverage_gap_id: str,
    probe_directive: dict[str, Any],
    detected_at_ms: int,
) -> dict[str, Any]:
    """Render a CuriosityClaim as an OCSF 2004 Detection Finding. The hypothesis statement +
    rationale + the cited ``coverage_gap_id`` + the probe directive ride in the ``unmapped``
    slot (a coverage-gap hypothesis is a *proactive* detection — what may be under-scanned)."""
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
            "product": {"name": "Nexus Curiosity", "vendor_name": "Nexus Cyber OS"},
        },
        "finding_info": {
            "uid": claim_id,
            "title": title,
            "types": ["coverage_gap_hypothesis"],
        },
        "unmapped": {
            "statement": statement,
            "rationale": rationale,
            "coverage_gap_id": coverage_gap_id,
            "probe_directive": probe_directive,
        },
    }
