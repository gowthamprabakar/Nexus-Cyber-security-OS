"""CVE x D.1-Vulnerability correlator (Task 7, Stage 3 CORRELATE).

Joins D.1 ``VulnerabilityFinding`` payloads (read from an operator-pinned
sibling workspace's ``findings.json``) against the CISA KEV catalog. For
each (D.1-finding, CVE-ID) pair where the CVE appears in KEV, emits a
single ``ThreatIntelFinding`` of type
``threat_intel_cve_in_kev_catalog`` at severity ``CRITICAL`` (KEV =
actively exploited per the CISA Known-Exploited-Vulnerabilities
catalog definition).

**Wire shapes consumed.** D.1 emits OCSF v1.3 Vulnerability Finding
(``class_uid 2002``). Each finding's ``vulnerabilities[].cve.uid``
holds the CVE ID. D.8 reads the wrapped OCSF dict; the
``VulnerabilityFinding`` wrapper (from ``vulnerability.schemas``)
validates the payload's class_uid + finding-id regex before exposing
``cve_ids`` and ``finding_id``.

**Sibling-workspace read.** Mirrors D.7's
``investigation.tools.related_findings._read_one`` pattern. Forgiving
on every failure mode: missing workspace, missing ``findings.json``,
malformed JSON, empty ``findings`` -> the correlator contributes zero
``ThreatIntelFinding``s but doesn't poison other correlators (Stage 3
fan-out under the agent driver, Task 12).

**ID convention.**

.. code-block:: text

   TI-CVE_KEV-<CVE_TOKEN>-NNN-<context>

   CVE_TOKEN  = the CVE ID with hyphens replaced by underscores,
                e.g., ``CVE_2024_12345`` for CVE-2024-12345.
   NNN        = 3-digit zero-padded sequence (per-correlator).
   context    = lowercase slug ``d1_vuln_<short-hex>`` where
                ``short-hex`` is a deterministic 8-char hash of the
                D.1 source finding id; the slug carries the D.1 finding-
                id linkage without inflating the threat-intel finding-id
                past validators.

**Resources carried forward.** The D.1 finding may carry
``affected_packages`` (one or more). D.8 v0.1 distills these into a
single ``AffectedResource`` per emitted finding -- ``resource_type =
"vulnerable_package"`` and ``identifier`` = ``<ecosystem>:<package>:
<version>`` of the first package -- which is enough for D.7
Investigation to walk the affected-package graph via the original D.1
finding (the linkage is in the evidence dict).

**No PII / no classifier substrings.** Q6 reminder: the correlator
operates on CVE IDs (public identifiers) and package coordinates (also
public). It does NOT carry over D.1 finding descriptions verbatim --
the D.8 finding's ``description`` is constructed from KEV + CVE
metadata only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from shared.fabric.envelope import NexusEnvelope
from vulnerability.schemas import VulnerabilityFinding

from threat_intel.schemas import (
    AffectedResource,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    build_finding,
)
from threat_intel.tools.cisa_kev import KevEntry

_LOG = logging.getLogger(__name__)

# CVE-ID regex shared across D.1 and D.8. Used for the validity check on
# the sibling-workspace CVE strings; mirrors the regex in D.1
# (vulnerability.schemas) verbatim.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def build_kev_index(entries: Iterable[KevEntry]) -> dict[str, KevEntry]:
    """Index a CISA KEV catalog by CVE ID for O(1) lookup.

    Built once per agent run (Stage 2 ENRICH) and passed to every
    correlator that joins on KEV (currently only CVE x D.1; future
    correlators may join on the same index).
    """
    return {entry.cve_id: entry for entry in entries}


async def correlate_cve_kev(
    *,
    vulnerability_workspace: Path | None,
    kev_index: Mapping[str, KevEntry],
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[ThreatIntelFinding, ...]:
    """Read D.1 findings + emit a ThreatIntelFinding per CVE-in-KEV match.

    Returns an empty tuple if ``vulnerability_workspace`` is ``None``
    (operator didn't pin a D.1 workspace -- correlator skipped),
    or if no D.1 findings expose CVE IDs that appear in
    ``kev_index``.

    The filesystem read happens in ``asyncio.to_thread`` so the agent
    driver (Task 12) can fan out the three correlators concurrently
    via ``asyncio.TaskGroup``.
    """
    if vulnerability_workspace is None:
        return ()
    if not kev_index:
        return ()

    raw_findings = await asyncio.to_thread(_read_d1_findings, vulnerability_workspace)
    if not raw_findings:
        return ()

    out: list[ThreatIntelFinding] = []
    sequence = 0
    for raw in raw_findings:
        try:
            vuln_finding = VulnerabilityFinding(raw)
        except (ValueError, KeyError, TypeError):
            continue
        for cve_id in vuln_finding.cve_ids:
            if not _CVE_ID_RE.match(cve_id):
                continue
            kev_entry = kev_index.get(cve_id)
            if kev_entry is None:
                continue
            sequence += 1
            finding = _build_cve_kev_finding(
                cve_id=cve_id,
                kev_entry=kev_entry,
                vuln_finding=vuln_finding,
                source_payload=raw,
                sequence=sequence,
                correlated_at=correlated_at,
                envelope=envelope,
            )
            out.append(finding)

    return tuple(out)


# ---------------------------------------------------------------------------
# Sibling-workspace read
# ---------------------------------------------------------------------------


def _read_d1_findings(workspace: Path) -> tuple[dict[str, Any], ...]:
    """Read findings.json from a D.1 Vulnerability workspace.

    Returns the raw class_uid=2002 dicts. Skips silently on missing
    file, malformed JSON, or non-2002 entries.
    """
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
        if raw.get("class_uid") != 2002:
            continue
        out.append(raw)
    return tuple(out)


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _build_cve_kev_finding(
    *,
    cve_id: str,
    kev_entry: KevEntry,
    vuln_finding: VulnerabilityFinding,
    source_payload: dict[str, Any],
    sequence: int,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> ThreatIntelFinding:
    cve_token = cve_id.replace("-", "_")
    context = _source_context(vuln_finding.finding_id)
    finding_id = f"TI-CVE_KEV-{cve_token}-{sequence:03d}-{context}"

    title = f"{cve_id} actively exploited (CISA KEV)"
    description = (
        f"{cve_id} ({kev_entry.vulnerability_name}) is listed in the CISA "
        f"Known Exploited Vulnerabilities catalog as of "
        f"{kev_entry.date_added.isoformat()}. "
        f"Vendor: {kev_entry.vendor_project}; product: {kev_entry.product}. "
        f"CISA-mandated remediation due date: "
        f"{kev_entry.due_date.isoformat() if kev_entry.due_date else 'not set'}."
    )

    affected = _affected_resources(source_payload, tenant_id=envelope.tenant_id)

    evidence: dict[str, Any] = {
        "kev_entry": {
            "cve_id": kev_entry.cve_id,
            "vendor_project": kev_entry.vendor_project,
            "product": kev_entry.product,
            "vulnerability_name": kev_entry.vulnerability_name,
            "date_added": kev_entry.date_added.isoformat(),
            "due_date": (
                kev_entry.due_date.isoformat() if kev_entry.due_date is not None else None
            ),
            "known_ransomware_campaign_use": kev_entry.known_ransomware_campaign_use,
            "required_action": kev_entry.required_action,
        },
        "source_d1_finding_id": vuln_finding.finding_id,
        "source_d1_finding_title": vuln_finding.title,
    }

    return build_finding(
        finding_id=finding_id,
        finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
        severity=Severity.CRITICAL,
        title=title,
        description=description,
        affected=affected,
        detected_at=correlated_at,
        envelope=envelope,
        evidence=evidence,
    )


def _source_context(d1_finding_id: str) -> str:
    """Derive a finding-id ``context`` slug from the D.1 source finding-id.

    The slug must match ``[a-z0-9_.-]+`` (the regex bracket for the
    ``context`` part of ``THREAT_INTEL_FINDING_ID_RE``). We hash the
    D.1 finding ID so the linkage stays deterministic without inflating
    the threat-intel finding-id past validator bounds.
    """
    digest = hashlib.sha256(d1_finding_id.encode("utf-8")).hexdigest()[:8]
    return f"d1_vuln_{digest}"


def _affected_resources(
    source_payload: dict[str, Any], *, tenant_id: str
) -> list[AffectedResource]:
    """Distill the D.1 finding's affected_packages into a D.8 AffectedResource.

    D.1's wire shape carries one or more ``affected_packages``; D.8 v0.1
    surfaces the first as a single ``vulnerable_package`` AffectedResource
    so the OCSF emit has at least one entry (``build_finding`` rejects
    empty ``affected``). Future versions may carry multi-package fan-out.

    AffectedResource (re-exported from ``cloud_posture.schemas``) requires
    6 non-empty fields. For non-cloud package resources we substitute
    ``"n/a"`` for the cloud-shape fields and synthesise an
    ``arn``-shaped identifier from the package coordinates so the OCSF
    `resources[].uid` stays unique per package.
    """
    packages = source_payload.get("affected_packages") or []
    first = packages[0] if (isinstance(packages, list) and packages) else None

    if isinstance(first, dict):
        name = str(first.get("name", "")) or "unknown"
        version = str(first.get("version", "")) or "unknown"
        ecosystem = str(first.get("ecosystem", "")) or "unknown"
        resource_id = f"{name}@{version}"
        arn = f"package:{ecosystem}:{name}@{version}"
    else:
        source_uid = str(source_payload.get("finding_info", {}).get("uid", "")) or "unknown"
        resource_id = source_uid
        arn = f"d1-finding:{source_uid}"

    return [
        AffectedResource(
            cloud="n/a",
            account_id=tenant_id or "n/a",
            region="n/a",
            resource_type="vulnerable_package",
            resource_id=resource_id,
            arn=arn,
        )
    ]


__all__ = ["build_kev_index", "correlate_cve_kev"]
