"""IOC x D.3-Runtime correlator (Task 9, Stage 3 CORRELATE).

Joins D.3 Runtime Threat findings (read from an operator-pinned sibling
workspace's ``findings.json``) against the shared IOC index built in
Stage 2 ENRICH. For each (D.3 finding, observable) pair where the
observable matches an ``IocEntity`` in the index, emits a single
``ThreatIntelFinding`` of type ``threat_intel_ioc_match_runtime``.

**Observables extracted from D.3 findings.**

  - ``affected_hosts[].ip[]`` -> ``(IocType.IP, ip)``
  - ``evidences[0].remote_ip`` (NETWORK findings) -> ``(IocType.IP, ip)``
  - ``evidences[0].file_hash`` /  ``sha256`` / ``sha1`` / ``md5``
    (FILE findings, when present) -> ``(IocType.FILE_HASH, ...)``
  - ``evidences[0].proc_hash`` /  ``process_hash`` /  ``binary_hash``
    (PROCESS findings, when present) -> ``(IocType.FILE_HASH, ...)``

**v0.1 reality.** D.3 v0.1's structured evidence dict carries
``proc_cmdline`` / ``file_path`` / ``remote_ip`` etc. but does NOT
guarantee file/process hashes -- those are forward-compatible keys.
v0.1 may emit zero IOC_MATCH_RUNTIME findings on the file/process-hash
side; the IP-match side carries the bulk of v0.1 hits. Future D.3
versions populating hash keys (or v0.2 abuse.ch / VirusTotal IOC
feeds) will exercise the file-hash path automatically.

**Severity, finding-id shape, sibling-workspace read posture, and
within-finding dedup all mirror Task 8** (``ioc_correlator_network``).

**ID convention.**

.. code-block:: text

   TI-IOC_RUN-<TYPE>_<TOKEN>-NNN-d3_run_<hash>

   TYPE   = uppercase IOC kind (IP / FILE_HASH / DOMAIN / URL).
   TOKEN  = the observable value with non [A-Z0-9_.] characters
            mapped to underscores.
   NNN    = 3-digit zero-padded sequence (per-correlator).
   hash   = deterministic 8-char SHA-256 of the source D.3 finding-id.

**No PII / no classifier substrings.** Q6 reminder: observables are
public-feed IOCs; descriptions are constructed from the matched
``IocEntity`` metadata, not from the source D.3 finding's title /
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

_TOKEN_SAFE_RE = re.compile(r"[^A-Za-z0-9_.]")

# Evidence-dict key names that may carry a FILE_HASH observable.
_FILE_HASH_KEYS = ("file_hash", "sha256", "sha1", "md5")
_PROCESS_HASH_KEYS = ("proc_hash", "process_hash", "binary_hash")


async def correlate_ioc_runtime(
    *,
    runtime_threat_workspace: Path | None,
    ioc_index: IocIndex,
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[ThreatIntelFinding, ...]:
    """Read D.3 findings + emit a ThreatIntelFinding per IOC match.

    Returns an empty tuple if ``runtime_threat_workspace`` is ``None``
    (operator didn't pin a D.3 workspace) or if no D.3 finding's
    observables hit the IOC index.
    """
    if runtime_threat_workspace is None:
        return ()
    if not ioc_index:
        return ()

    raw_findings = await asyncio.to_thread(_read_d3_findings, runtime_threat_workspace)
    if not raw_findings:
        return ()

    out: list[ThreatIntelFinding] = []
    sequence = 0
    for raw in raw_findings:
        source_finding_id = str(raw.get("finding_info", {}).get("uid", ""))
        if not source_finding_id:
            continue
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


def _read_d3_findings(workspace: Path) -> tuple[dict[str, Any], ...]:
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


def _extract_observables(d3_finding: dict[str, Any]) -> list[tuple[IocType, str]]:
    """Pull IP / FILE_HASH observables out of a D.3 finding payload."""
    out: list[tuple[IocType, str]] = []

    for host in d3_finding.get("affected_hosts") or []:
        if not isinstance(host, dict):
            continue
        ip_field = host.get("ip")
        if isinstance(ip_field, list):
            for ip in ip_field:
                if isinstance(ip, str) and ip:
                    out.append((IocType.IP, ip))
        elif isinstance(ip_field, str) and ip_field:
            out.append((IocType.IP, ip_field))

    evidences = d3_finding.get("evidences") or []
    if isinstance(evidences, list) and evidences and isinstance(evidences[0], dict):
        ev = evidences[0]
        remote_ip = ev.get("remote_ip")
        if isinstance(remote_ip, str) and remote_ip:
            out.append((IocType.IP, remote_ip))
        for key in _FILE_HASH_KEYS + _PROCESS_HASH_KEYS:
            value = ev.get(key)
            if isinstance(value, str) and value:
                out.append((IocType.FILE_HASH, value))

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
    finding_id = f"TI-IOC_RUN-{type_token}_{value_token}-{sequence:03d}-{context}"

    title = f"IOC match: {ioc_type.value}={value} in D.3 runtime finding"
    description = (
        f"D.3 Runtime Threat finding {source_finding_id} carries observable "
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
        "source_d3_finding_id": source_finding_id,
        "source_d3_finding_title": str(source_payload.get("finding_info", {}).get("title", "")),
        "observable_match": {"type": ioc_type.value, "value": value},
    }

    return build_finding(
        finding_id=finding_id,
        finding_type=ThreatIntelFindingType.IOC_MATCH_RUNTIME,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=correlated_at,
        envelope=envelope,
        evidence=evidence,
    )


def _severity_from_confidence(confidence: float) -> Severity:
    if confidence >= 0.8:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def _value_token(value: str) -> str:
    return _TOKEN_SAFE_RE.sub("_", value).upper()


def _source_context(d3_finding_id: str) -> str:
    digest = hashlib.sha256(d3_finding_id.encode("utf-8")).hexdigest()[:8]
    return f"d3_run_{digest}"


def _affected_resources(
    source_payload: dict[str, Any], *, tenant_id: str
) -> list[AffectedResource]:
    """Project D.3's ``affected_hosts`` into a D.8 ``AffectedResource``.

    D.3 carries host-shaped entries (hostname, host_uid, image_ref,
    namespace). D.8 synthesises:

      cloud / region  = ``n/a`` (D.3 workloads are agent-side, not
                        cloud-control-plane-side).
      account_id      = envelope.tenant_id.
      resource_type   = ``"workload_host"``.
      resource_id     = the host's hostname (or host uid).
      arn             = ``"host:<hostname>"`` or ``"host:<uid>"``.
    """
    hosts = source_payload.get("affected_hosts") or []
    hostname = ""
    host_uid = ""
    if isinstance(hosts, list) and hosts and isinstance(hosts[0], dict):
        first = hosts[0]
        h = first.get("hostname")
        if isinstance(h, str):
            hostname = h
        u = first.get("uid")
        if isinstance(u, str):
            host_uid = u

    if hostname:
        resource_id = hostname
        arn = f"host:{hostname}"
    elif host_uid:
        resource_id = host_uid
        arn = f"host:{host_uid}"
    else:
        source_uid = str(source_payload.get("finding_info", {}).get("uid", "")) or "unknown"
        resource_id = source_uid
        arn = f"d3-finding:{source_uid}"

    return [
        AffectedResource(
            cloud="n/a",
            account_id=tenant_id or "n/a",
            region="n/a",
            resource_type="workload_host",
            resource_id=resource_id,
            arn=arn,
        )
    ]


__all__ = ["correlate_ioc_runtime"]
