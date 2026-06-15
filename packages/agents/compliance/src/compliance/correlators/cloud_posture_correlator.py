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
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from compliance.correlators.control_index import ControlIndex, IndexedMapping
from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    ControlMapping,
    build_finding,
    severity_for_level,
)
from compliance.tools.cis_aws_benchmark import CisControl

_LOG = logging.getLogger(__name__)

# A-3: native-CIS attribution. cloud-posture findings carry Prowler's OWN CIS
# controls in evidence.cis_controls (e.g. "CIS-3.0:1.10"). We consume only the
# version matching the loaded framework (cis_aws_v3 = v3.x) and only control_ids
# that actually exist in the catalog — never fabricated, never cross-version.
_NATIVE_SOURCE_RULE_ID = "prowler_native_cis"
_NATIVE_CIS_VERSION_PREFIX = "CIS-3"


def _normalize_framework(key: str) -> str:
    """Normalize a Prowler compliance-framework key for version matching.

    Handles the format variants Prowler uses across surfaces (``CIS-3.0`` /
    ``cis_3.0_aws`` / mixed case) → uppercase, separators unified to ``-``.
    """
    return re.sub(r"[ _]", "-", key).upper()


def _extract_native_cis_control_ids(payload: dict[str, Any]) -> list[str]:
    """Pull native CIS-v3 control ids from a finding's ``evidences[].cis_controls``.

    Each entry is ``"<framework>:<control_id>"`` (A-3 PR1 emission). Keeps only
    entries whose framework normalizes to the loaded version (``CIS-3*``); returns
    control ids in first-seen order, de-duped. Cross-version (CIS-2.x) is dropped.
    """
    evidences = payload.get("evidences")
    if not isinstance(evidences, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for evidence in evidences:
        if not isinstance(evidence, dict):
            continue
        cis_controls = evidence.get("cis_controls")
        if not isinstance(cis_controls, list):
            continue
        for entry in cis_controls:
            if not isinstance(entry, str):
                continue
            framework, separator, control_id = entry.rpartition(":")
            if not separator or not control_id:
                continue
            if not _normalize_framework(framework).startswith(_NATIVE_CIS_VERSION_PREFIX):
                continue
            if control_id not in seen:
                seen.add(control_id)
                out.append(control_id)
    return out


def _native_indexed_mapping(control: CisControl) -> IndexedMapping:
    """Build an IndexedMapping for a native-CIS attribution (synthetic mapping)."""
    return IndexedMapping(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id=control.control_id,
        control_name=control.name,
        control_description=control.description,
        mapping=ControlMapping(
            source_agent="cloud_posture",
            source_rule_id=_NATIVE_SOURCE_RULE_ID,
            control_id=control.control_id,
            level=control.level,
            required=control.required,
        ),
    )


async def correlate_cloud_posture(
    *,
    cloud_posture_workspace: Path | None,
    control_index: ControlIndex,
    correlated_at: datetime,
    envelope: NexusEnvelope,
    controls_by_id: Mapping[str, CisControl] | None = None,
) -> tuple[ComplianceFinding, ...]:
    """Read F.3 findings + emit per-mapping ComplianceFindings.

    Two attribution passes:

    1. **YAML source_mappings** — the hand-curated ``(cloud_posture, rule_id)`` →
       CIS-control index (the existing path).
    2. **Native CIS (A-3)** — when ``controls_by_id`` is supplied, consume Prowler's
       OWN CIS attributions from each finding's ``evidence.cis_controls`` for any
       control_id that exists in the loaded v3 catalog (version-matched, never
       fabricated). De-duped against pass 1 per (source finding, control_id).

    Returns ``()`` when no workspace is pinned, or neither attribution source has
    anything to emit.
    """
    if cloud_posture_workspace is None:
        return ()
    if not control_index and not controls_by_id:
        return ()

    raw_findings = await asyncio.to_thread(_read_f3_findings, cloud_posture_workspace)
    if not raw_findings:
        return ()

    out: list[ComplianceFinding] = []
    sequence = 0
    emitted: set[tuple[str, str]] = set()

    # Pass 1 — YAML source_mappings.
    for raw in raw_findings:
        rule_id = _extract_rule_id(raw)
        if not rule_id:
            continue
        mappings = control_index.get(("cloud_posture", rule_id))
        if not mappings:
            continue
        source_finding_id = _extract_source_finding_id(raw) or "unknown"
        for indexed in mappings:
            sequence += 1
            emitted.add((source_finding_id, indexed.control_id))
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

    # Pass 2 — native CIS attribution (A-3), de-duped against pass 1.
    if controls_by_id:
        for raw in raw_findings:
            source_finding_id = _extract_source_finding_id(raw) or "unknown"
            for control_id in _extract_native_cis_control_ids(raw):
                control = controls_by_id.get(control_id)
                if control is None:
                    continue
                if (source_finding_id, control_id) in emitted:
                    continue
                emitted.add((source_finding_id, control_id))
                sequence += 1
                out.append(
                    _build_compliance_finding(
                        indexed=_native_indexed_mapping(control),
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
