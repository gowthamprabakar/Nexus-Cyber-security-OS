"""OCSF v1.3 Incident Finding (class_uid 2005) builder for ranked AttackPaths (P2).

``build_incident_finding`` converts one ``(AttackPath, expected_loss, blast)``
tuple into an OCSF v1.3 Incident Finding dict wrapped in a ``NexusEnvelope``,
following the pattern established by ``aispm/schemas._base_payload`` and
``investigation/schemas.IncidentReport.to_ocsf``.

Design invariants
-----------------
- ``finding_info.uid`` == ``attack_path_external_id(path)`` — identical to the
  ATTACK_PATH graph node's ``external_id`` (Task 1 / P1), so SIEM consumers
  dedup on the same stable key as the graph.
- ``finding_info.types[0]`` == ``"attack_path_<path_type>"`` — ADR-020 discriminator.
- ``evidences`` carries CVE ids / data-type labels only — **NO plaintext secrets**
  (security invariant: evidence is ids/types, no credential material).
- Wrapped in ``NexusEnvelope(agent_id="meta-harness")``.  The caller supplies
  the envelope fields (correlation_id, nlah_version, model_pin,
  charter_invocation_id) so the builder stays pure/testable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope, wrap_ocsf

from meta_harness.attack_path_writer import attack_path_external_id
from meta_harness.attack_paths import AttackPath

# ---------------------------------------------------------------------------
# OCSF constants
# ---------------------------------------------------------------------------

_OCSF_VERSION = "1.3.0"
_CATEGORY_UID = 2  # Findings
_CATEGORY_NAME = "Findings"
_CLASS_UID = 2005  # Incident Finding
_CLASS_NAME = "Incident Finding"
_ACTIVITY_CREATE = 1  # Activity 1 = "Create"
_STATUS_NEW = 1

# type_uid = class_uid * 100 + activity_id  (aispm pattern, aispm/schemas.py:153)
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_CREATE


# ---------------------------------------------------------------------------
# Severity mapping: int score (0-100) -> OCSF severity_id (1-6)
# ---------------------------------------------------------------------------
# OCSF v1.3 severity_id bands (standard):
#   1 = Informational  (<30)
#   2 = Low            (30-59)
#   3 = Medium         (60-74)
#   4 = High           (75-84)
#   5 = Critical       (85-94)
#   6 = Fatal          (>=95)
#
# Aligned with the fleet's _SEVERITY dict (attack_paths.py:38-63): lowest
# registered severity is 58, highest is 95 (crown_jewel).  Bands chosen so
# crown_jewel (95) → 6 (Fatal) and fine_grained_data (60) → 3 (Medium).
_SEVERITY_ID_TO_NAME: dict[int, str] = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}


def _score_to_severity_id(score: int) -> int:
    """Map a 0-100 integer severity score to an OCSF severity_id (1-6)."""
    if score < 30:
        return 1
    if score < 60:
        return 2
    if score < 75:
        return 3
    if score < 85:
        return 4
    if score < 95:
        return 5
    return 6


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_incident_finding(
    path: AttackPath,
    expected_loss: float,
    blast: int,
    *,
    tenant_id: str,
    now: datetime,
    envelope: NexusEnvelope | None = None,
) -> dict[str, Any]:
    """Build an OCSF v1.3 Incident Finding (class_uid 2005) for a ranked AttackPath.

    The returned dict is wrapped in a ``NexusEnvelope`` via ``wrap_ocsf``.
    When ``envelope`` is ``None`` a minimal stub envelope is created with
    ``agent_id="meta-harness"`` and placeholder values for the remaining
    required envelope fields; in production the caller should pass the live
    envelope so the finding carries the full audit chain.

    Args:
        path:          The ranked ``AttackPath`` to export.
        expected_loss: Annualised expected loss in USD (from the ranker).
        blast:         Blast-radius count (number of downstream nodes reachable).
        tenant_id:     Tenant / customer id (threaded from ``scan_run``).
        now:           Caller-supplied timestamp (scan boundary).  Used for
                       ``first_seen_time`` / ``last_seen_time`` and the OCSF
                       ``time`` field.
        envelope:      Optional pre-built ``NexusEnvelope``.  Defaults to a
                       minimal stub with ``agent_id="meta-harness"``.

    Returns:
        A wrapped OCSF v1.3 dict (``nexus_envelope`` key present).

    Security invariant:
        ``evidences`` carries only CVE ids and data-type labels from
        ``path.evidence`` plus the ``sink_id`` identifier.  No plaintext
        secret material (API keys, tokens, credentials) is included.
    """
    uid = attack_path_external_id(path)
    severity_id = _score_to_severity_id(path.severity)
    timestamp_ms = int(now.timestamp() * 1000)
    time_iso = now.isoformat()

    # Build evidences list — ids/types only, never plaintext secrets.
    evidence_entries: list[dict[str, Any]] = [
        {"type": "evidence", "value": ev} for ev in path.evidence
    ]
    if path.sink_id:
        evidence_entries.append({"type": "sink_id", "value": path.sink_id})

    # Build resources list — one entry per entity id.
    resources: list[dict[str, Any]] = [
        {"type": "attack_path_entity", "uid": entity_id} for entity_id in path.entities
    ]

    payload: dict[str, Any] = {
        "metadata": {
            "version": _OCSF_VERSION,
            "product": {
                "name": "Nexus Attack Path Analyzer",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "activity_id": _ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Create",
        "severity_id": severity_id,
        "severity": _SEVERITY_ID_TO_NAME[severity_id],
        "time": timestamp_ms,
        "time_dt": time_iso,
        "status_id": _STATUS_NEW,
        "status": "New",
        "finding_info": {
            "uid": uid,
            "title": path.title,
            "types": [f"attack_path_{path.path_type}"],
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
        },
        "resources": resources,
        "evidences": evidence_entries,
        # Extended fields carrying moat-specific signals.
        "risk_score": int(expected_loss),
        "unmapped": {
            "tenant_id": tenant_id,
            "path_type": path.path_type,
            "severity_score": path.severity,
            "expected_loss": expected_loss,
            "blast_radius": blast,
            "count": path.count,
            "kev": path.kev,
            "epss": path.epss,
        },
    }

    if envelope is None:
        envelope = NexusEnvelope(
            correlation_id="",
            tenant_id=tenant_id,
            agent_id="meta-harness",
            nlah_version="",
            model_pin="",
            charter_invocation_id="",
        )

    return wrap_ocsf(payload, envelope)


__all__ = ["build_incident_finding"]
