"""Stage-4 AGGREGATE — per-control PASS/FAIL roll-up.

Per Q4 of the D.9 v0.1 plan: the Stage-3 correlators (Tasks 6 + 7)
emit one ``ComplianceFinding`` per *(source-finding, CIS-control)*
pair. The aggregator collapses those into **one finding per
(control, status-change) tuple** so downstream consumers (Stage 5
SCORE, Stage 6 SUMMARIZE) see one PASS/FAIL verdict per control
rather than per source-finding.

**Roll-up rule (Q4).** For each unique ``compliance.control`` value
seen across the correlator emits:

- ``status = FAIL`` if any contributing per-mapping finding has
  severity ``>= MEDIUM`` (the canonical FAIL-on-MEDIUM gate).
- ``status = PASS`` otherwise (only LOW contributors).
- v0.1 ships **FAIL-only output** — PASS-only controls are
  omitted from the agent's findings.json. v0.2 lifts this for
  attestation-export (every covered control gets a PASS/FAIL
  record).

**Severity at emit time.** ``max()`` over contributing severities.
Task 9's scorer then canonicalises via the severity-for-level
table -- the scorer is the single source of truth.

**Resource union.** Every unique resource across contributors is
carried forward. Dedup by ``arn`` (the canonical OCSF
``resources[].uid`` field).

**Finding-id convention.**

.. code-block:: text

   COMPLIANCE-CIS_AWS_V3-<control_token>-NNN-aggregated

   <control_token> = CIS control id with `.` -> `_`
                     (matches Task 6 + 7 token format).
   NNN             = 3-digit zero-padded sequence ordered by
                     control_id (deterministic across runs with
                     identical inputs).
   context         = literal ``aggregated`` so downstream
                     consumers can filter aggregator output
                     from raw correlator output.

**Evidence shape.** Carries the full list of contributing per-
mapping findings + source-finding provenance:

.. code-block:: python

   {
     "aggregated_status": "FAIL",
     "contributor_count": <int>,
     "contributing_finding_ids": [<list of per-mapping
                                   ComplianceFinding ids>],
     "contributing_source_findings": [
       {"agent": "cloud_posture", "finding_id": <id>,
        "rule_id": <id>},
       {"agent": "data_security", ...},
       ...
     ],
     "control": {"framework": ..., "control_id": ...,
                 "level": ..., "required": ...},
   }

The ``control`` block is sourced from the **first** contributing
finding's control evidence (all contributors share the same
control, so any of them is correct).

**Q6 reminder.** This module reads structured fields from the
per-mapping inputs only. No verbatim source-finding text is
reproduced.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    Severity,
    build_finding,
    severity_to_id,
)

# FAIL gate per Q4. Severities >= MEDIUM trigger a per-control FAIL
# emit; only LOW-severity contributors collapse to PASS (and are
# omitted from v0.1 output).
_FAIL_FLOOR = Severity.MEDIUM


def aggregate_controls(
    findings: Sequence[ComplianceFinding],
    *,
    envelope: NexusEnvelope,
    aggregated_at: datetime,
) -> tuple[ComplianceFinding, ...]:
    """Collapse per-mapping ComplianceFindings into per-control roll-ups.

    Input findings are typically the union of Task 6 + Task 7
    correlator outputs. Output is ordered by ``compliance.control``
    (deterministic across runs with identical inputs).
    """
    if not findings:
        return ()

    groups = _group_by_control(findings)
    if not groups:
        return ()

    out: list[ComplianceFinding] = []
    sequence = 0
    # Deterministic ordering — sort by control_id (the bit after the colon).
    for control_key in sorted(groups.keys()):
        contributors = groups[control_key]
        max_severity = _max_severity(contributors)
        if severity_to_id(max_severity) < severity_to_id(_FAIL_FLOOR):
            # v0.1: PASS-only controls omitted from output.
            continue
        sequence += 1
        out.append(
            _build_aggregated_finding(
                control_key=control_key,
                contributors=contributors,
                max_severity=max_severity,
                sequence=sequence,
                envelope=envelope,
                aggregated_at=aggregated_at,
            )
        )
    return tuple(out)


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def _group_by_control(
    findings: Iterable[ComplianceFinding],
) -> dict[str, list[ComplianceFinding]]:
    """Group input findings by their ``compliance.control`` value.

    Findings whose ``compliance.control`` field is missing or
    malformed are silently skipped — they couldn't have come from
    a well-formed correlator emit anyway.
    """
    out: dict[str, list[ComplianceFinding]] = {}
    for f in findings:
        control = _extract_control(f)
        if not control:
            continue
        out.setdefault(control, []).append(f)
    return out


def _extract_control(f: ComplianceFinding) -> str:
    payload = f.to_dict()
    compliance = payload.get("compliance")
    if not isinstance(compliance, dict):
        return ""
    control = compliance.get("control")
    return str(control) if isinstance(control, str) else ""


def _max_severity(findings: Iterable[ComplianceFinding]) -> Severity:
    """Return the highest severity across contributors."""
    best_id = 0
    best: Severity = Severity.INFO
    for f in findings:
        s = f.severity
        sid = severity_to_id(s)
        if sid > best_id:
            best_id = sid
            best = s
    return best


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------


def _build_aggregated_finding(
    *,
    control_key: str,
    contributors: list[ComplianceFinding],
    max_severity: Severity,
    sequence: int,
    envelope: NexusEnvelope,
    aggregated_at: datetime,
) -> ComplianceFinding:
    framework_value, control_id = _parse_control_key(control_key)
    framework = ComplianceFramework(framework_value)
    control_token = control_id.replace(".", "_")
    finding_id = f"COMPLIANCE-{framework_value.upper()}-{control_token}-{sequence:03d}-aggregated"

    # The first contributor carries the right control metadata
    # (level/required/name) -- all contributors share the same
    # control_id so any of them is correct.
    first = contributors[0]
    title = first.title
    description = (
        f"CIS {control_id} aggregate verdict: {len(contributors)} contributing "
        f"source-finding{'s' if len(contributors) != 1 else ''} produced this "
        f"control failure. Max severity = {max_severity.value}."
    )

    affected = _merge_resources(contributors)
    evidence = _build_aggregated_evidence(
        framework_value=framework_value,
        control_id=control_id,
        contributors=contributors,
    )

    return build_finding(
        finding_id=finding_id,
        framework=framework,
        control_id=control_id,
        severity=max_severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=aggregated_at,
        envelope=envelope,
        evidence=evidence,
    )


def _parse_control_key(control_key: str) -> tuple[str, str]:
    """Split ``"cis_aws_v3:1.1"`` into ``("cis_aws_v3", "1.1")``."""
    framework, _, control_id = control_key.partition(":")
    return framework, control_id


def _merge_resources(
    contributors: list[ComplianceFinding],
) -> list[AffectedResource]:
    """Union every contributor's resource list, dedup by arn.

    AffectedResource construction may fail on partial / synthetic
    fallback entries — we skip those silently so a downstream
    aggregator emit still has at least one resource.
    """
    seen: set[str] = set()
    out: list[AffectedResource] = []
    fallback: AffectedResource | None = None
    for f in contributors:
        for raw in f.resources:
            if not isinstance(raw, dict):
                continue
            arn = str(raw.get("uid", ""))
            if not arn or arn in seen:
                continue
            seen.add(arn)
            resource = _reconstruct_resource(raw)
            if resource is None:
                continue
            if fallback is None:
                fallback = resource
            out.append(resource)
    if out:
        return out
    if fallback is not None:
        return [fallback]
    # Last resort -- synthesise a minimal resource so build_finding
    # accepts the emit. This branch is reached only if every
    # contributor's resources[] failed reconstruction.
    return [
        AffectedResource(
            cloud="n/a",
            account_id="n/a",
            region="n/a",
            resource_type="compliance_aggregated",
            resource_id="unknown",
            arn="aggregated:unknown",
        )
    ]


def _reconstruct_resource(raw: dict[str, Any]) -> AffectedResource | None:
    arn = str(raw.get("uid", ""))
    resource_type = str(raw.get("type", ""))
    cloud = str(raw.get("cloud_partition", ""))
    region = str(raw.get("region", ""))
    owner = raw.get("owner")
    account_id = str(owner.get("account_uid", "")) if isinstance(owner, dict) else ""
    if not arn or not resource_type:
        return None
    resource_id = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    try:
        return AffectedResource(
            cloud=cloud or "n/a",
            account_id=account_id or "n/a",
            region=region or "n/a",
            resource_type=resource_type,
            resource_id=resource_id or arn,
            arn=arn,
        )
    except (TypeError, ValueError):
        return None


def _build_aggregated_evidence(
    *,
    framework_value: str,
    control_id: str,
    contributors: list[ComplianceFinding],
) -> dict[str, Any]:
    """Carry the full contributor list in evidence (Q4 traceability)."""
    contributing_ids: list[str] = []
    source_findings: list[dict[str, Any]] = []
    control_meta: dict[str, Any] = {
        "framework": framework_value,
        "control_id": control_id,
    }
    for f in contributors:
        contributing_ids.append(f.finding_id)
        payload = f.to_dict()
        evidences = payload.get("evidences") or []
        if isinstance(evidences, list) and evidences and isinstance(evidences[0], dict):
            ev = evidences[0]
            src = ev.get("source_finding")
            if isinstance(src, dict):
                source_findings.append(dict(src))
            ctrl = ev.get("control")
            if isinstance(ctrl, dict) and not control_meta.get("level"):
                # First seen wins -- all contributors share the same
                # (level, required) per control.
                if "level" in ctrl:
                    control_meta["level"] = ctrl["level"]
                if "required" in ctrl:
                    control_meta["required"] = ctrl["required"]

    return {
        "aggregated_status": "FAIL",
        "contributor_count": len(contributors),
        "contributing_finding_ids": contributing_ids,
        "contributing_source_findings": source_findings,
        "control": control_meta,
    }


__all__ = ["aggregate_controls"]
