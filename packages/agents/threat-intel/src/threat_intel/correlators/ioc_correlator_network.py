"""IOC x D.4-Network correlator (Task 8, Stage 3 CORRELATE).

Joins D.4 Network Threat findings (read from an operator-pinned sibling
workspace's ``findings.json``) against the shared IOC index built in
Stage 2 ENRICH. For each (D.4 finding, observable) pair where the
observable matches an ``IocEntity`` in the index, emits a single
``ThreatIntelFinding`` of type ``threat_intel_ioc_match_network``.

**Observables extracted from D.4 findings.**

  - ``affected_networks[].ip`` -> ``(IocType.IP, ip)``
  - ``affected_networks[].traffic.dst_ip`` -> ``(IocType.IP, dst_ip)``
  - ``evidences[0].src_ip`` / ``dst_ip`` -> ``(IocType.IP, ...)``
  - ``evidences[0].query_name`` (DGA finding) -> ``(IocType.DOMAIN, ...)``
  - CVE-ID regex matches inside ``evidences[0].signature`` (SURICATA
    finding) -> ``(IocType.CVE_ID, "CVE-YYYY-NNNN")``

URL observables are NOT extracted in v0.1 (D.4 doesn't carry URLs as a
top-level field; freeform signature-text URL parsing is deferred to
v0.2 alongside the abuse.ch / VirusTotal URL-IOC feeds).

**Severity selection.** Derived from ``IocEntity.confidence`` at emit
time (v0.1 simple table; Task 10 scorer formalises the matrix):

  - confidence >= 0.8 -> ``Severity.HIGH``
  - 0.5 <= confidence < 0.8 -> ``Severity.MEDIUM``
  - confidence < 0.5 -> ``Severity.LOW``

**Sibling-workspace read.** Mirrors the forgiving-on-failure posture
from D.7's ``investigation.tools.related_findings`` + the CVE
correlator (Task 7). Missing workspace, missing/malformed
``findings.json``, non-2004 entries, malformed D.4 finding-id values
all silently skipped. Filesystem I/O via ``asyncio.to_thread``
(ADR-005).

**ID convention.**

.. code-block:: text

   TI-IOC_NET-<TYPE>_<TOKEN>-NNN-d4_net_<hash>

   TYPE   = uppercase IOC kind (IP / DOMAIN / CVE_ID).
   TOKEN  = the observable value with non [A-Z0-9_.] characters
            mapped to underscores, e.g. ``1_2_3_4`` for 1.2.3.4 or
            ``CVE_2024_12345`` for CVE-2024-12345.
   NNN    = 3-digit zero-padded sequence (per-correlator).
   hash   = deterministic 8-char SHA-256 of the source D.4 finding-id.

**Deduplication within run.** The same D.4 finding may surface the
same IOC twice (e.g., src_ip == dst_ip, or evidence src_ip == affected-
networks ip). The correlator emits at most ONE
``ThreatIntelFinding`` per (D.4 finding-id, IOC type, IOC value) triple.

**No PII / no classifier substrings.** Q6 reminder: observables are
public-feed IOCs; descriptions are constructed from the matched
``IocEntity`` metadata, not from the source D.4 finding's title /
description verbatim.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from threat_intel.correlators.ioc_index import IocIndex
from threat_intel.entities import IocEntity
from threat_intel.schemas import (
    AffectedResource,
    IocType,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    build_finding,
)

_LOG = logging.getLogger(__name__)

_CVE_ID_IN_TEXT_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# Map dotted IP / hyphenated CVE / dotted domain into the FINDING_ID
# token bracket ``[A-Z0-9_.]+`` -- substitute any character outside that
# set with ``_`` then uppercase.
_TOKEN_SAFE_RE = re.compile(r"[^A-Za-z0-9_.]")


async def correlate_ioc_network(
    *,
    network_threat_workspace: Path | None,
    ioc_index: IocIndex,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[ThreatIntelFinding, ...]:
    """Read D.4 findings + emit a ThreatIntelFinding per IOC match.

    Returns an empty tuple if ``network_threat_workspace`` is ``None``
    (operator didn't pin a D.4 workspace) or if no D.4 finding's
    observables hit the IOC index.

    The filesystem read happens in ``asyncio.to_thread`` so the agent
    driver (Task 12) can fan out the three correlators concurrently
    via ``asyncio.TaskGroup``.
    """
    if network_threat_workspace is None:
        return ()
    if not ioc_index:
        return ()

    raw_findings = await asyncio.to_thread(_read_d4_findings, network_threat_workspace)
    if not raw_findings:
        return ()

    out: list[ThreatIntelFinding] = []
    sequence = 0
    for raw in raw_findings:
        source_finding_id = str(raw.get("finding_info", {}).get("uid", ""))
        if not source_finding_id:
            continue
        # Per-finding dedup so the same observable inside one D.4
        # finding doesn't emit twice.
        seen_in_finding: set[tuple[IocType, str]] = set()
        for ioc_type, value in _extract_observables(raw):
            key = (ioc_type, value)
            if key in seen_in_finding:
                continue
            seen_in_finding.add(key)
            ioc_entity = ioc_index.get(key)
            if ioc_entity is None:
                continue
            sequence += 1
            out.append(
                _build_ioc_match_finding(
                    ioc_type=ioc_type,
                    value=value,
                    ioc_entity=ioc_entity,
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


def _read_d4_findings(workspace: Path) -> tuple[dict[str, Any], ...]:
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
        if raw.get("class_uid") != 2004:
            continue
        out.append(raw)
    return tuple(out)


# ---------------------------------------------------------------------------
# Observable extraction
# ---------------------------------------------------------------------------


def _extract_observables(d4_finding: dict[str, Any]) -> list[tuple[IocType, str]]:
    """Pull IP / DOMAIN / CVE-ID observables out of a D.4 finding payload.

    Order doesn't matter for correctness (per-finding dedup handles it)
    but stays deterministic for predictable finding-id sequencing.
    """
    out: list[tuple[IocType, str]] = []

    for net in d4_finding.get("affected_networks") or []:
        if not isinstance(net, dict):
            continue
        ip = net.get("ip")
        if isinstance(ip, str) and ip:
            out.append((IocType.IP, ip))
        traffic = net.get("traffic") or {}
        if isinstance(traffic, dict):
            dst_ip = traffic.get("dst_ip")
            if isinstance(dst_ip, str) and dst_ip:
                out.append((IocType.IP, dst_ip))

    evidences = d4_finding.get("evidences") or []
    if isinstance(evidences, list) and evidences and isinstance(evidences[0], dict):
        ev = evidences[0]
        for key in ("src_ip", "dst_ip"):
            value = ev.get(key)
            if isinstance(value, str) and value:
                out.append((IocType.IP, value))
        query_name = ev.get("query_name")
        if isinstance(query_name, str) and query_name:
            out.append((IocType.DOMAIN, query_name))
        signature = ev.get("signature")
        if isinstance(signature, str) and signature:
            for match in _CVE_ID_IN_TEXT_RE.findall(signature):
                out.append((IocType.CVE_ID, match))

    return out


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _build_ioc_match_finding(
    *,
    ioc_type: IocType,
    value: str,
    ioc_entity: IocEntity,
    source_payload: dict[str, Any],
    source_finding_id: str,
    sequence: int,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> ThreatIntelFinding:
    severity = _severity_from_confidence(ioc_entity.confidence)

    type_token = ioc_type.value.upper()
    value_token = _value_token(value)
    context = _source_context(source_finding_id)
    finding_id = f"TI-IOC_NET-{type_token}_{value_token}-{sequence:03d}-{context}"

    title = f"IOC match: {ioc_type.value}={value} in D.4 network finding"
    description = (
        f"D.4 Network Threat finding {source_finding_id} carries observable "
        f"{ioc_type.value}={value!r}, which matches the IOC index entry "
        f"from feed {ioc_entity.source_feed!r} (confidence "
        f"{ioc_entity.confidence:.2f}, first seen "
        f"{ioc_entity.first_seen.isoformat()})."
    )

    affected = _affected_resources(source_payload, tenant_id=envelope.tenant_id)

    evidence: dict[str, Any] = {
        "ioc_entry": {
            "ioc_type": ioc_entity.ioc_type.value,
            "value": ioc_entity.value,
            "confidence": ioc_entity.confidence,
            "source_feed": ioc_entity.source_feed,
            "first_seen": ioc_entity.first_seen.isoformat(),
            "last_seen": ioc_entity.last_seen.isoformat(),
        },
        "source_d4_finding_id": source_finding_id,
        "source_d4_finding_title": str(source_payload.get("finding_info", {}).get("title", "")),
        "observable_match": {"type": ioc_type.value, "value": value},
    }

    return build_finding(
        finding_id=finding_id,
        finding_type=ThreatIntelFindingType.IOC_MATCH_NETWORK,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=correlated_at,
        envelope=envelope,
        evidence=evidence,
    )


def _severity_from_confidence(confidence: float) -> Severity:
    """Map IocEntity.confidence to correlator-emit severity.

    v0.1 table; Task 10 (scorer) may further canonicalise.
    """
    if confidence >= 0.8:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def _value_token(value: str) -> str:
    """Convert an arbitrary observable value into a FINDING_ID_RE-safe token.

    The threat-intel finding-id regex's token bracket allows
    ``[A-Z0-9_.]+``. Lowercase letters get uppercased; any other char
    (``.``, ``-``, ``/``, ``:`` ...) becomes ``_``.
    """
    return _TOKEN_SAFE_RE.sub("_", value).upper()


def _source_context(d4_finding_id: str) -> str:
    """Derive a finding-id ``context`` slug from the D.4 source finding-id."""
    digest = hashlib.sha256(d4_finding_id.encode("utf-8")).hexdigest()[:8]
    return f"d4_net_{digest}"


def _affected_resources(
    source_payload: dict[str, Any], *, tenant_id: str
) -> list[AffectedResource]:
    """Project D.4's ``affected_networks`` into a D.8 ``AffectedResource``.

    D.4 carries network-shaped affected entries (src_ip / dst_ip). For
    D.8's general-purpose AffectedResource, we synthesise:

      cloud / region / account_id  = ``n/a`` / from envelope.
      resource_type                = ``"network_endpoint"``.
      resource_id                  = ``"<src_ip> -> <dst_ip>"`` (or
                                     just src_ip if no dst).
      arn                          = ``"network:<src_ip>[:<dst_ip>]"``.
    """
    nets = source_payload.get("affected_networks") or []
    src_ip = ""
    dst_ip = ""
    if isinstance(nets, list) and nets and isinstance(nets[0], dict):
        first = nets[0]
        ip_field = first.get("ip")
        if isinstance(ip_field, str):
            src_ip = ip_field
        traffic = first.get("traffic") or {}
        if isinstance(traffic, dict):
            d = traffic.get("dst_ip")
            if isinstance(d, str):
                dst_ip = d

    if src_ip and dst_ip:
        resource_id = f"{src_ip} -> {dst_ip}"
        arn = f"network:{src_ip}:{dst_ip}"
    elif src_ip:
        resource_id = src_ip
        arn = f"network:{src_ip}"
    else:
        source_uid = str(source_payload.get("finding_info", {}).get("uid", "")) or "unknown"
        resource_id = source_uid
        arn = f"d4-finding:{source_uid}"

    return [
        AffectedResource(
            cloud="n/a",
            account_id=tenant_id or "n/a",
            region="n/a",
            resource_type="network_endpoint",
            resource_id=resource_id,
            arn=arn,
        )
    ]


__all__ = ["correlate_ioc_network"]
