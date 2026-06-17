"""D.5 Data Security x CIS-control correlator (Task 7, Stage 3 CORRELATE).

Mirrors Task 6's ``cloud_posture_correlator`` exactly. The only
deltas:

- Reads from ``--data-security-workspace`` instead of
  ``--cloud-posture-workspace``.
- Looks up the control index under
  ``("data_security", <rule_id>)`` rather than
  ``("cloud_posture", <rule_id>)``.
- Synthesises finding-id ``context`` as ``d5_<hash>`` rather than
  ``f3_<hash>`` so the source-agent provenance survives in the
  finding id.

D.5 emits class_uid 2003 (re-uses F.3's ``build_finding``) with the
**short rule_id** in ``compliance.control`` (``s3_bucket_public``,
``s3_bucket_unencrypted``, ``s3_oversharing_iam``,
``s3_object_sensitive_in_untrusted_location``). The full
``DataSecurityFindingType.value`` lands in
``evidence.source_finding_type`` but D.9 joins on
``compliance.control`` for symmetry with Task 6.

**Severity at emit time.** Same canonical
``severity_for_level(mapping.level, required=mapping.required)``
table as Task 6. Task 9's scorer is the single source of truth.

**Sibling-workspace read.** Same forgiving-on-failure posture as
Task 6: missing workspace, missing/malformed ``findings.json``,
non-2003 entries, missing ``compliance.control`` all silently
skipped. Filesystem I/O via ``asyncio.to_thread`` (ADR-005).

**ID convention.**

.. code-block:: text

   COMPLIANCE-CIS_AWS_V3-<control_id>-NNN-d5_<hash>

   <control_id> = CIS control id with `.` -> `_`.
   NNN          = 3-digit zero-padded sequence (per-correlator).
   hash         = deterministic 8-char SHA-256 of the source D.5
                  finding-id.

**Q6 reminder.** Descriptions come from the bundled (paraphrased)
CIS control metadata. Source D.5 finding's title / description NOT
reproduced verbatim. **Classifier-matched substring posture from
D.5's Q6**: D.5's findings carry classifier labels but NOT the
matched substrings; D.9 inherits that posture by reading only
structured fields.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from compliance.correlators.control_index import ControlIndex, IndexedMapping
from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    build_finding,
    severity_for_level,
)

_LOG = logging.getLogger(__name__)


async def correlate_data_security(
    *,
    data_security_workspace: Path | None,
    control_index: ControlIndex,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[ComplianceFinding, ...]:
    """Read D.5 findings + emit per-mapping ComplianceFindings.

    Returns an empty tuple if ``data_security_workspace`` is ``None``
    (operator didn't pin a D.5 workspace) or if no D.5 finding's
    rule_id hits the control index.
    """
    if data_security_workspace is None:
        return ()
    if not control_index:
        return ()

    raw_findings = await asyncio.to_thread(_read_d5_findings, data_security_workspace)
    if not raw_findings:
        return ()

    out: list[ComplianceFinding] = []
    sequence = 0
    for raw in raw_findings:
        rule_id = _extract_rule_id(raw)
        if not rule_id:
            continue
        key = ("data_security", rule_id)
        mappings = control_index.get(key)
        if not mappings:
            continue
        source_finding_id = _extract_source_finding_id(raw) or "unknown"
        for indexed in mappings:
            sequence += 1
            out.append(
                _build_compliance_finding(
                    indexed=indexed,
                    source_payload=raw,
                    source_finding_id=source_finding_id,
                    sequence=sequence,
                    correlated_at=correlated_at,
                    envelope=envelope,
                )
            )
    return tuple(out)


# ---------------------------------------------------------------------------
# Sibling-workspace read
# ---------------------------------------------------------------------------


def _read_d5_findings(workspace: Path) -> tuple[dict[str, Any], ...]:
    findings_path = workspace / "findings.json"
    if not findings_path.is_file():
        return ()
    try:
        report = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _LOG.warning("skipping malformed findings.json at %s: %s", findings_path, exc)
        return ()
    if not isinstance(report, dict):
        return ()

    raw_findings = report.get("findings", []) or []
    if not isinstance(raw_findings, list):
        return ()

    out: list[dict[str, Any]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        if raw.get("class_uid") != 2003:
            continue
        out.append(raw)
    return tuple(out)


def _extract_rule_id(payload: dict[str, Any]) -> str:
    """Pull the D.5 rule id from ``compliance.control`` of the OCSF payload.

    D.5's detectors stamp short rule_ids (``s3_bucket_public`` etc.)
    here; the longer ``DataSecurityFindingType.value`` discriminator
    lives in ``evidence.source_finding_type`` but we don't read from
    there in v0.1.
    """
    compliance = payload.get("compliance")
    if not isinstance(compliance, dict):
        return ""
    rule_id = compliance.get("control")
    return str(rule_id) if isinstance(rule_id, str) else ""


def _extract_source_finding_id(payload: dict[str, Any]) -> str:
    info = payload.get("finding_info")
    if not isinstance(info, dict):
        return ""
    uid = info.get("uid")
    return str(uid) if isinstance(uid, str) else ""


# ---------------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------------


def _build_compliance_finding(
    *,
    indexed: IndexedMapping,
    source_payload: dict[str, Any],
    source_finding_id: str,
    sequence: int,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> ComplianceFinding:
    severity = severity_for_level(indexed.mapping.level, required=indexed.mapping.required)
    control_token = indexed.control_id.replace(".", "_")
    context = _source_context(source_finding_id)
    finding_id = f"COMPLIANCE-CIS_AWS_V3-{control_token}-{sequence:03d}-{context}"

    title = f"CIS {indexed.control_id} — {indexed.control_name}"
    description = (
        f"CIS {indexed.control_id} failed via D.5 Data Security finding "
        f"{source_finding_id} (rule_id={indexed.mapping.source_rule_id}). "
        f"{indexed.control_description}"
    )

    affected = _project_resources(source_payload, envelope=envelope)
    if not affected:
        affected = [_fallback_resource(source_finding_id, envelope=envelope)]

    evidence: dict[str, Any] = {
        "source_finding": {
            "agent": "data_security",
            "finding_id": source_finding_id,
            "rule_id": indexed.mapping.source_rule_id,
        },
        "control": {
            "framework": indexed.framework.value,
            "control_id": indexed.control_id,
            "level": indexed.mapping.level.value,
            "required": indexed.mapping.required,
        },
    }

    return build_finding(
        finding_id=finding_id,
        framework=indexed.framework,
        control_id=indexed.control_id,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=correlated_at,
        envelope=envelope,
        evidence=evidence,
    )


def _project_resources(
    payload: dict[str, Any], *, envelope: NexusEnvelope
) -> list[AffectedResource]:
    """Project D.5's OCSF ``resources`` into the D.9 AffectedResource shape.

    Identical projection to Task 6's F.3 correlator -- both source
    agents emit the same OCSF v1.3 2003 resource shape because both
    re-use ``cloud_posture.schemas.build_finding``.
    """
    raw_resources = payload.get("resources") or []
    out: list[AffectedResource] = []
    if not isinstance(raw_resources, list):
        return out
    for raw in raw_resources:
        if not isinstance(raw, dict):
            continue
        arn = str(raw.get("uid", ""))
        resource_type = str(raw.get("type", ""))
        cloud = str(raw.get("cloud_partition", ""))
        region = str(raw.get("region", ""))
        owner = raw.get("owner")
        account_id = str(owner.get("account_uid", "")) if isinstance(owner, dict) else ""
        account_id = account_id or envelope.tenant_id or "n/a"
        if not arn or not resource_type:
            continue
        resource_id = _derive_resource_id_from_arn(arn) or arn
        try:
            out.append(
                AffectedResource(
                    cloud=cloud or "n/a",
                    account_id=account_id,
                    region=region or "n/a",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    arn=arn,
                )
            )
        except (TypeError, ValueError):
            continue
    return out


def _derive_resource_id_from_arn(arn: str) -> str:
    for sep in ("/", ":"):
        if sep in arn:
            tail = arn.rsplit(sep, 1)[-1]
            if tail:
                return tail
    return arn


def _fallback_resource(source_finding_id: str, *, envelope: NexusEnvelope) -> AffectedResource:
    return AffectedResource(
        cloud="n/a",
        account_id=envelope.tenant_id or "n/a",
        region="n/a",
        resource_type="compliance_source_finding",
        resource_id=source_finding_id or "unknown",
        arn=f"d5-finding:{source_finding_id or 'unknown'}",
    )


def _source_context(source_finding_id: str) -> str:
    """Derive a finding-id ``context`` slug from the D.5 source finding-id."""
    digest = hashlib.sha256(source_finding_id.encode("utf-8")).hexdigest()[:8]
    return f"d5_{digest}"


__all__ = ["correlate_data_security"]
