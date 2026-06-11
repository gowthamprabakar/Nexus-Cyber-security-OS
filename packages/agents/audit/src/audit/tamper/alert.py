"""Tamper-alert OCSF 6003 finding emission (audit v0.2 Task 8, Q5/WI-F9).

When tamper detection (Task 7) finds a break, F.6 emits an OCSF v1.3 API Activity (class_uid
6003) **alert** record per finding — carrying ``broken_chain_id``, ``last_valid_entry``,
``suspected_tamper_point``, and ``tamper_category``. Per **WI-F9** a chain break **always**
surfaces an alert, never silently; per **WI-F2** the alert only reports — F.6 never repairs.

The alert reuses the 6003 envelope but a distinct ``activity_name`` + a critical severity, so
the normal audit-record ``to_ocsf`` path (WI-F5) is untouched. Constants are local here — no
``schemas.py`` edit, so the offline eval stays byte-identical.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from audit.schemas import (
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AuditEvent,
)
from audit.tamper.detect import TamperFinding, detect_tampering

#: OCSF severity_id 5 == Critical — chain tampering is a P0 integrity event.
OCSF_SEVERITY_CRITICAL = 5
TAMPER_ALERT_ACTIVITY_NAME = "Audit chain tamper detected"


def _last_valid_entry(events: Sequence[AuditEvent], suspected_correlation_id: str) -> str:
    """The correlation id of the last entry before the suspected tamper point (``genesis`` if
    the break is at the first entry)."""
    last = "genesis"
    for event in events:
        if event.correlation_id == suspected_correlation_id:
            return last
        last = event.correlation_id
    return last


def build_tamper_alert(
    chain_id: str, events: Sequence[AuditEvent], finding: TamperFinding
) -> dict[str, Any]:
    """Render one tamper finding as an OCSF 6003 alert record."""
    return {
        "metadata": {"version": OCSF_VERSION, "product": {"name": "Nexus Audit Agent"}},
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_name": TAMPER_ALERT_ACTIVITY_NAME,
        "severity_id": OCSF_SEVERITY_CRITICAL,
        "api": {"operation": "tamper_alert"},
        "unmapped": {
            "broken_chain_id": chain_id,
            "last_valid_entry": _last_valid_entry(events, finding.correlation_id),
            "suspected_tamper_point": finding.correlation_id,
            "tamper_category": finding.category.value,
            "detail": finding.detail,
        },
    }


def emit_tamper_alerts(chain_id: str, events: Sequence[AuditEvent]) -> tuple[dict[str, Any], ...]:
    """Emit one OCSF 6003 alert per tamper finding (empty iff the chain is intact). WI-F9: a
    break always surfaces — never silent. WI-F2: report-only, never repair."""
    return tuple(build_tamper_alert(chain_id, events, f) for f in detect_tampering(events))
