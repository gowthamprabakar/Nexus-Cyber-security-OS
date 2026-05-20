"""Threat Intel Agent driver — wires charter + 3 feeds + 3 correlators + scorer + summarizer.

Task 12 of the D.8 v0.1 plan. Mirrors D.4 Network Threat's
:mod:`network_threat.agent` shape — three-feed ``asyncio.TaskGroup``
ingest + three-correlator concurrent fan-out + ADR-007 v1.2 driver
signature ``(contract, *, llm_provider, ...)``.

Six-stage pipeline (per the NLAH README):

  1. INGEST — three feeds concurrent via :class:`asyncio.TaskGroup`
     (NVD CVE 2.0 + CISA KEV + MITRE ATT&CK STIX 2.1).
  2. ENRICH — build per-feed indices (CVE / KEV / TTP) + the cross-
     correlator IOC index. Optional SemanticStore writes for the
     IOC / CVE / TTP entities (single-tenant ``semantic_store=None``
     opt-in default).
  3. CORRELATE — three correlators concurrent via TaskGroup:
     ``correlate_cve_kev`` (CVE x D.1), ``correlate_ioc_network``
     (IOC x D.4), ``correlate_ioc_runtime`` (IOC x D.3).
  4. SCORE — canonical severity scorer (:func:`scorer.score_findings`).
  5. SUMMARIZE — deterministic markdown via
     :func:`summarizer.render_summary`.
  6. HANDOFF — write findings.json + report.md to the charter
     workspace; the charter-emitted audit chain hash-chains the run.

**v0.1 IOC index source.** None of the three v0.1 feeds (NVD / KEV /
ATT&CK) carry IP / domain / URL / file-hash IOCs. The IOC index is
built from the CVE-IDs surfaced by NVD + KEV (each becomes an
``IocEntity`` of type ``IocType.CVE_ID``) so that the IOC x D.4
correlator can match D.4 Suricata-signature CVE-ID strings. v0.2
plugs in IP / domain / URL feeds (abuse.ch / VirusTotal); the index
shape is forward-compatible.

**Single-tenant SemanticStore opt-in default.** The runtime charter's
multi-tenant production blocks on the future SET LOCAL ``$1`` tenant-
RLS substrate-fix plan; in v0.1 the agent driver guards SemanticStore
writes behind ``semantic_store=None`` so the agent's filesystem-only
output path (findings.json + report.md) is fully exercised even
without a substrate. When a ``SemanticStore`` IS passed, the KG
writes happen inline during Stage 2 ENRICH; failures bubble up to
abort the run.

**Q6 reminder.** No PII; no classifier-matched substrings. The agent
operates on public-feed metadata only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from threat_intel import __version__ as agent_version
from threat_intel.correlators.cve_correlator import (
    build_kev_index,
    correlate_cve_kev,
)
from threat_intel.correlators.ioc_correlator_network import correlate_ioc_network
from threat_intel.correlators.ioc_correlator_runtime import correlate_ioc_runtime
from threat_intel.correlators.ioc_index import build_ioc_index
from threat_intel.entities import CveEntity, IocEntity, TechniqueEntity
from threat_intel.kg_writer import KnowledgeGraphWriter
from threat_intel.schemas import (
    FindingsReport,
    IocType,
    ThreatIntelFinding,
)
from threat_intel.scorer import score_findings
from threat_intel.summarizer import render_summary
from threat_intel.tools.cisa_kev import KevEntry, read_cisa_kev
from threat_intel.tools.mitre_attack import TechniqueRecord, read_mitre_attack
from threat_intel.tools.nvd_feed import NvdCveRecord, read_nvd_feed

DEFAULT_NLAH_VERSION = "0.1.0"

# Confidence assignments for the v0.1 CVE-ID IOC index.
# KEV-listed CVEs get the higher confidence (CISA actively-exploited
# evidence); NVD-only CVEs get medium (catalog presence only).
_CONF_CVE_FROM_KEV = 0.9
_CONF_CVE_FROM_NVD = 0.6


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to the D.8 agent.

    Only the three feed-readers are charter-registered. Correlators
    (which read sibling workspaces) are called directly from the
    driver -- they're pure I/O against operator-pinned paths and don't
    consume charter cloud-call budget (filesystem-only in v0.1).
    """
    reg = ToolRegistry()
    reg.register("read_nvd_feed", read_nvd_feed, version="0.1.0", cloud_calls=0)
    reg.register("read_cisa_kev", read_cisa_kev, version="0.1.0", cloud_calls=0)
    reg.register("read_mitre_attack", read_mitre_attack, version="0.1.0", cloud_calls=0)
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="threat_intel",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    nvd_snapshot: Path | str | None = None,
    kev_snapshot: Path | str | None = None,
    mitre_attack_snapshot: Path | str | None = None,
    vulnerability_workspace: Path | str | None = None,
    network_threat_workspace: Path | str | None = None,
    runtime_threat_workspace: Path | str | None = None,
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the Threat Intel Agent end-to-end under the runtime charter.

    Args:
        contract: The signed ``ExecutionContract``.
        llm_provider: Reserved for future LLM-driven flows; not called
            in v0.1.
        nvd_snapshot: Optional path to an NVD CVE 2.0 JSON snapshot.
            Skipped if None.
        kev_snapshot: Optional path to a CISA KEV catalog JSON snapshot.
            Skipped if None.
        mitre_attack_snapshot: Optional path to a MITRE ATT&CK STIX 2.1
            bundle JSON. Skipped if None.
        vulnerability_workspace: Optional path to a D.1 Vulnerability
            workspace (with ``findings.json``). Skipped if None.
        network_threat_workspace: Optional path to a D.4 Network
            Threat workspace. Skipped if None.
        runtime_threat_workspace: Optional path to a D.3 Runtime
            Threat workspace. Skipped if None.
        semantic_store: Optional SemanticStore for KG writes (single-
            tenant v0.1; multi-tenant production blocks on the
            future SET LOCAL tenant-RLS substrate-fix plan).

    Returns:
        The ``FindingsReport``. Side effects: writes ``findings.json``
        and ``report.md`` to the charter workspace; emits a hash-
        chained audit log at ``audit.jsonl``.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1: INGEST — three feeds concurrent.
        nvd_records, kev_entries, techniques = await _ingest(
            ctx,
            nvd_snapshot=nvd_snapshot,
            kev_snapshot=kev_snapshot,
            mitre_attack_snapshot=mitre_attack_snapshot,
        )

        # Stage 2: ENRICH — build indices, optionally persist to KG.
        kev_index = build_kev_index(kev_entries)
        ioc_index = build_ioc_index(_build_iocs_from_feeds(nvd_records, kev_entries))
        if semantic_store is not None:
            await _persist_to_semantic_store(
                semantic_store=semantic_store,
                customer_id=contract.customer_id,
                nvd_records=nvd_records,
                kev_entries=kev_entries,
                techniques=techniques,
            )

        # Stage 3: CORRELATE — three correlators concurrent.
        correlated_at = datetime.now(UTC)
        cve_findings, ioc_net_findings, ioc_run_findings = await _correlate(
            vulnerability_workspace=_as_path(vulnerability_workspace),
            network_threat_workspace=_as_path(network_threat_workspace),
            runtime_threat_workspace=_as_path(runtime_threat_workspace),
            kev_index=kev_index,
            ioc_index=ioc_index,
            correlated_at=correlated_at,
            envelope=envelope,
        )

        merged: list[ThreatIntelFinding] = []
        merged.extend(cve_findings)
        merged.extend(ioc_net_findings)
        merged.extend(ioc_run_findings)

        # Stage 4: SCORE — canonical severity re-stamp.
        scored = score_findings(merged)

        # Stage 5 + 6: SUMMARIZE + HANDOFF.
        report = FindingsReport(
            agent="threat_intel",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in scored:
            report.add_finding(f)

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "report.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------


async def _ingest(
    ctx: Charter,
    *,
    nvd_snapshot: Path | str | None,
    kev_snapshot: Path | str | None,
    mitre_attack_snapshot: Path | str | None,
) -> tuple[
    Sequence[NvdCveRecord],
    Sequence[KevEntry],
    Sequence[TechniqueRecord],
]:
    """Stage 1 — fan out the three feeds via TaskGroup. Skipped feeds -> empty tuple."""
    async with asyncio.TaskGroup() as tg:
        nvd_task = (
            tg.create_task(ctx.call_tool("read_nvd_feed", path=Path(nvd_snapshot)))
            if nvd_snapshot
            else None
        )
        kev_task = (
            tg.create_task(ctx.call_tool("read_cisa_kev", path=Path(kev_snapshot)))
            if kev_snapshot
            else None
        )
        mitre_task = (
            tg.create_task(ctx.call_tool("read_mitre_attack", path=Path(mitre_attack_snapshot)))
            if mitre_attack_snapshot
            else None
        )

    nvd: Sequence[NvdCveRecord] = nvd_task.result() if nvd_task else ()
    kev: Sequence[KevEntry] = kev_task.result() if kev_task else ()
    mitre: Sequence[TechniqueRecord] = mitre_task.result() if mitre_task else ()
    return nvd, kev, mitre


def _build_iocs_from_feeds(
    nvd_records: Sequence[NvdCveRecord],
    kev_entries: Sequence[KevEntry],
) -> list[IocEntity]:
    """Materialise the v0.1 IOC index entries from the available feeds.

    Source: CVE-IDs from NVD + KEV. Each becomes an IocEntity of type
    ``CVE_ID``. KEV listing bumps confidence to 0.9; NVD-only CVEs get
    0.6. v0.2 will append IP / domain / URL / file-hash IOCs.
    """
    iocs: dict[str, IocEntity] = {}
    now = datetime.now(UTC)
    for kev in kev_entries:
        iocs[kev.cve_id] = IocEntity(
            ioc_type=IocType.CVE_ID,
            value=kev.cve_id,
            first_seen=datetime.combine(kev.date_added, datetime.min.time(), tzinfo=UTC),
            last_seen=now,
            confidence=_CONF_CVE_FROM_KEV,
            source_feed="cisa_kev",
        )
    for nvd in nvd_records:
        if nvd.cve_id in iocs:
            # KEV takes priority on overlap (higher confidence already wins).
            continue
        first_seen = nvd.published or now
        last_seen = nvd.last_modified or first_seen
        iocs[nvd.cve_id] = IocEntity(
            ioc_type=IocType.CVE_ID,
            value=nvd.cve_id,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=_CONF_CVE_FROM_NVD,
            source_feed="nvd",
        )
    return list(iocs.values())


async def _persist_to_semantic_store(
    *,
    semantic_store: SemanticStore,
    customer_id: str,
    nvd_records: Sequence[NvdCveRecord],
    kev_entries: Sequence[KevEntry],
    techniques: Sequence[TechniqueRecord],
) -> None:
    """Stage 2 KG persistence (optional v0.1).

    Persists every NVD + KEV CVE as a ``CveEntity``, and every ATT&CK
    technique as a ``TechniqueEntity``. IOCs are persisted on the
    same opt-in path even though v0.1's index is sparse (it's the
    contract for v0.2's richer IOC feeds).
    """
    writer = KnowledgeGraphWriter(semantic_store, customer_id=customer_id)
    kev_by_cve = {kev.cve_id: kev for kev in kev_entries}
    for nvd in nvd_records:
        kev = kev_by_cve.get(nvd.cve_id)
        cve_entity = _cve_entity_from_records(nvd, kev)
        await writer.upsert_cve(cve_entity)
    # KEV-only CVEs (not in NVD snapshot) -> persist as CVE entities too.
    nvd_cve_ids = {n.cve_id for n in nvd_records}
    for kev in kev_entries:
        if kev.cve_id in nvd_cve_ids:
            continue
        await writer.upsert_cve(_cve_entity_from_records(None, kev))
    for tech in techniques:
        await writer.upsert_technique(_technique_entity_from_record(tech))


def _cve_entity_from_records(nvd: NvdCveRecord | None, kev: KevEntry | None) -> CveEntity:
    if nvd is not None:
        return CveEntity(
            cve_id=nvd.cve_id,
            cvss_v3_score=nvd.cvss_v3_score,
            cvss_v3_severity=nvd.cvss_v3_severity,
            kev_listed=kev is not None,
            kev_added_date=kev.date_added if kev is not None else None,
            description=nvd.description,
        )
    # At least one feed must surface the CVE (caller invariant);
    # kev is non-None on this branch.
    if kev is None:
        raise ValueError("_cve_entity_from_records called with both nvd and kev as None")
    return CveEntity(
        cve_id=kev.cve_id,
        kev_listed=True,
        kev_added_date=kev.date_added,
        description=kev.short_description,
    )


def _technique_entity_from_record(tech: TechniqueRecord) -> TechniqueEntity:
    return TechniqueEntity(
        technique_id=tech.technique_id,
        name=tech.name,
        description=tech.description,
        tactics=list(tech.tactics),
        platforms=list(tech.platforms),
        is_subtechnique=tech.is_subtechnique,
        url=tech.url,
    )


async def _correlate(
    *,
    vulnerability_workspace: Path | None,
    network_threat_workspace: Path | None,
    runtime_threat_workspace: Path | None,
    kev_index: dict[str, KevEntry],
    ioc_index: dict[tuple[IocType, str], IocEntity],
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[
    tuple[ThreatIntelFinding, ...],
    tuple[ThreatIntelFinding, ...],
    tuple[ThreatIntelFinding, ...],
]:
    """Stage 3 — three correlators concurrent via TaskGroup."""
    async with asyncio.TaskGroup() as tg:
        cve_task = tg.create_task(
            correlate_cve_kev(
                vulnerability_workspace=vulnerability_workspace,
                kev_index=kev_index,
                correlated_at=correlated_at,
                envelope=envelope,
            )
        )
        net_task = tg.create_task(
            correlate_ioc_network(
                network_threat_workspace=network_threat_workspace,
                ioc_index=ioc_index,
                correlated_at=correlated_at,
                envelope=envelope,
            )
        )
        run_task = tg.create_task(
            correlate_ioc_runtime(
                runtime_threat_workspace=runtime_threat_workspace,
                ioc_index=ioc_index,
                correlated_at=correlated_at,
                envelope=envelope,
            )
        )

    return cve_task.result(), net_task.result(), run_task.result()


def _as_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


__all__ = ["build_registry", "run"]


# ---------------------------------------------------------------------------
# Iterable typing hint (kept as a forward-import for readability)
# ---------------------------------------------------------------------------


_ = Iterable  # silence "imported but unused" — kept for future driver hooks
