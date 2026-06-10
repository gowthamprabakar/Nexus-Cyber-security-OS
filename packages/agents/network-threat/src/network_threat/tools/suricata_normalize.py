"""Suricata live alert normalization (D.4 v0.2 Task 3).

Turns a raw Suricata ``eve.json`` event dict into the same `SuricataAlert` the offline
path produces (reusing its parse helpers, so downstream stays byte-identical), plus
alert-metadata enrichment (signature id / classtype / severity / action). The receive
timestamp is **caller-provided** (`received_at`) so the normalizer stays deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from network_threat.schemas import SuricataAlert
from network_threat.tools.suricata_reader import (
    _collect_unmapped,
    _parse_severity,
    _parse_timestamp,
)


@dataclass(frozen=True, slots=True)
class SuricataEnrichment:
    signature_id: int = 0
    classtype: str = ""
    severity: str = ""
    action: str = ""


@dataclass(frozen=True, slots=True)
class NormalizedSuricataAlert:
    alert: SuricataAlert
    enrichment: SuricataEnrichment


def normalize_suricata_event(
    raw: dict[str, Any], *, received_at: datetime
) -> NormalizedSuricataAlert | None:
    """Normalize a raw eve.json event → ``(SuricataAlert, SuricataEnrichment)``. Returns
    `None` for non-``alert`` events or malformed alerts (forgiving). ``received_at`` is
    used when the event carries no own timestamp."""
    if raw.get("event_type") != "alert":
        return None
    alert_blob = raw.get("alert")
    if not isinstance(alert_blob, dict):
        return None
    severity = _parse_severity(alert_blob.get("severity"))
    if severity is None:
        return None

    try:
        alert = SuricataAlert(
            timestamp=_parse_timestamp(raw.get("timestamp")) or received_at,
            src_ip=str(raw.get("src_ip", "")),
            dst_ip=str(raw.get("dest_ip", "")),
            src_port=int(raw.get("src_port", 0)),
            dst_port=int(raw.get("dest_port", 0)),
            protocol=str(raw.get("proto", "")),
            signature_id=int(alert_blob.get("signature_id", 0)),
            signature=str(alert_blob.get("signature", "")),
            category=str(alert_blob.get("category", "")),
            severity=severity,
            rev=int(alert_blob.get("rev", 1)),
            unmapped=_collect_unmapped(raw, alert_blob),
        )
    except (ValidationError, ValueError, TypeError):
        return None

    enrichment = SuricataEnrichment(
        signature_id=alert.signature_id,
        classtype=alert.category,
        severity=str(alert.severity.value if hasattr(alert.severity, "value") else alert.severity),
        action=str(alert_blob.get("action", "")),
    )
    return NormalizedSuricataAlert(alert=alert, enrichment=enrichment)
