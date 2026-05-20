"""F.3 Cloud Posture x CIS-control correlator (Task 6, Stage 3 CORRELATE).

Reads F.3 Cloud Posture findings (OCSF class_uid 2003) from an
operator-pinned sibling workspace's ``findings.json``. For each F.3
finding whose ``compliance.control`` rule_id is referenced by one or
more CIS controls in the bundled library (via the
``source_mappings`` field), emits one per-mapping
``ComplianceFinding``. Task 8's aggregator collapses these into
per-control PASS/FAIL roll-ups; Task 9's scorer canonicalises
severity.

**Severity at emit time.** Each correlator emits at
``severity_for_level(mapping.level, required=mapping.required)`` --
the per-mapping table-driven default. Task 9's scorer is the single
canonical source of truth.

**Sibling-workspace read.** Mirrors D.8's forgiving-on-failure
posture exactly: missing workspace, missing/malformed
``findings.json``, non-2003 entries, missing ``compliance.control``
field all silently skipped. Filesystem I/O via ``asyncio.to_thread``
(ADR-005).

**ID convention.**

.. code-block:: text

   COMPLIANCE-CIS_AWS_V3-<control_id>-NNN-f3_<hash>

   <control_id> = CIS control id with `.` -> `_`
                  (e.g., "1.1" -> "1_1", "2.1.5" -> "2_1_5").
   NNN          = 3-digit zero-padded sequence (per-correlator).
   hash         = deterministic 8-char SHA-256 of the source F.3
                  finding-id.

**Within-finding dedup.** The same source F.3 finding may surface a
rule_id that maps to multiple CIS controls (e.g.,
``CSPM-AWS-S3-001`` triggers both 2.1.4 and 2.1.5). The correlator
emits one ComplianceFinding per (F.3 finding, CIS control) pair --
the aggregator (Task 8) collapses across F.3 findings to produce a
single per-control verdict.

**Resource propagation.** D.6 carries forward F.3's ``resources``
list verbatim so the compliance finding can be traced back to the
exact AWS resources that failed the control.

**Q6 reminder.** Descriptions are constructed from the bundled CIS
control metadata (paraphrased, in-house). The source F.3 finding's
title / description is NOT reproduced verbatim in D.6's output.
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


async def correlate_cloud_posture(
    *,
    cloud_posture_workspace: Path | None,
    control_index: ControlIndex,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[ComplianceFinding, ...]:
    """Read F.3 findings + emit per-mapping ComplianceFindings.

    Returns an empty tuple if ``cloud_posture_workspace`` is ``None``
    (operator didn't pin an F.3 workspace) or if no F.3 finding's
    rule_id hits the control index.
    """
    if cloud_posture_workspace is None:
        return ()
    if not control_index:
        return ()

    raw_findings = await asyncio.to_thread(_read_f3_findings, cloud_posture_workspace)
    if not raw_findings:
        return ()

    out: list[ComplianceFinding] = []
    sequence = 0
    for raw in raw_findings:
        rule_id = _extract_rule_id(raw)
        if not rule_id:
            continue
        key = ("cloud_posture", rule_id)
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


def _read_f3_findings(workspace: Path) -> tuple[dict[str, Any], ...]:
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
    """Pull the F.3 rule id from ``compliance.control`` of the OCSF payload."""
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
        f"CIS {indexed.control_id} failed via F.3 Cloud Posture finding "
        f"{source_finding_id} (rule_id={indexed.mapping.source_rule_id}). "
        f"{indexed.control_description}"
    )

    affected = _project_resources(source_payload, envelope=envelope)
    if not affected:
        affected = [_fallback_resource(source_finding_id, envelope=envelope)]

    evidence: dict[str, Any] = {
        "source_finding": {
            "agent": "cloud_posture",
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
    """Reconstruct AffectedResource records from F.3's OCSF ``resources``.

    F.3 emits ``resources[].type`` / ``uid`` (ARN) / ``cloud_partition`` /
    ``region`` / ``owner.account_uid``. We invert that to the
    cloud_posture.schemas.AffectedResource shape (6-field). Bad / partial
    entries fall through to the synthesised fallback at caller scope.
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
        # Fall back to envelope tenant_id when F.3 didn't carry the
        # owner block (older fixtures).
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
    """Pull the last segment of an ARN as a stable short resource_id.

    AWS ARN shapes vary; the last `:` or `/` segment usually carries
    the resource name. Falls back to the full ARN.
    """
    for sep in ("/", ":"):
        if sep in arn:
            tail = arn.rsplit(sep, 1)[-1]
            if tail:
                return tail
    return arn


def _fallback_resource(source_finding_id: str, *, envelope: NexusEnvelope) -> AffectedResource:
    """Construct a synthetic resource when F.3 didn't carry one.

    AffectedResource requires 6 non-empty fields. Older / partial F.3
    fixtures may not populate `resources[]`; we still need to emit a
    valid compliance finding so the aggregator (Task 8) can see the
    control failure.
    """
    return AffectedResource(
        cloud="n/a",
        account_id=envelope.tenant_id or "n/a",
        region="n/a",
        resource_type="compliance_source_finding",
        resource_id=source_finding_id or "unknown",
        arn=f"f3-finding:{source_finding_id or 'unknown'}",
    )


def _source_context(source_finding_id: str) -> str:
    """Derive a finding-id ``context`` slug from the F.3 source finding-id."""
    digest = hashlib.sha256(source_finding_id.encode("utf-8")).hexdigest()[:8]
    return f"f3_{digest}"


__all__ = ["correlate_cloud_posture"]
