"""TDD test — threat-intel agent persists IOC nodes via upsert_ioc (Task 7).

Asserts that after ``run()`` with NVD/KEV snapshot feeds, ``ioc`` nodes are
present in the SemanticStore graph with ``external_id = "{type}:{value}"``
matching the IOCs derived from the feeds.

The v0.1 IOC index is built from CVE-IDs (``IocType.CVE_ID``), so the
expected external_id is ``cve_id:{cve_id}`` for each feed entry.

Test harness mirrors ``tests/integration/test_wiring.py``:
- uses ``in_memory_semantic_store`` (aiosqlite)
- patches feed readers at agent module level (same monkeypatch pattern)
- queries ``store.list_entities_by_type`` for ``entity_type="ioc"``
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from fleet_testkit import in_memory_semantic_store
from threat_intel import agent as agent_mod
from threat_intel.agent import run
from threat_intel.tools.cisa_kev import KevEntry
from threat_intel.tools.nvd_feed import NvdCveRecord

_CVE_ID = "CVE-2021-44228"
_CUSTOMER_ID = "acme"
_NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="threat_intel",
        customer_id=_CUSTOMER_ID,
        task="Threat intel scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_nvd_feed", "read_cisa_kev", "read_mitre_attack"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=_NOW,
        expires_at=datetime(2026, 5, 21, 12, 5, 0, tzinfo=UTC),
    )


def _kev(cve_id: str = _CVE_ID) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j2 RCE",
        date_added=date(2021, 12, 10),
        short_description="Log4Shell",
        required_action="Apply updates.",
        due_date=date(2021, 12, 24),
        known_ransomware_campaign_use=True,
        notes="",
        cwes=["CWE-20", "CWE-917"],
    )


def _nvd(cve_id: str = _CVE_ID) -> NvdCveRecord:
    return NvdCveRecord(
        cve_id=cve_id,
        description="Log4j RCE",
        published=datetime(2021, 12, 10, tzinfo=UTC),
        last_modified=datetime(2021, 12, 20, tzinfo=UTC),
        vuln_status="Analyzed",
        cvss_v3_score=10.0,
        cvss_v3_severity="CRITICAL",
        references=[],
    )


def _patch_readers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    nvd: list[NvdCveRecord] | None = None,
    kev: list[KevEntry] | None = None,
) -> None:
    async def fake_nvd(*, path: Path, **_: Any) -> tuple[NvdCveRecord, ...]:
        del path
        return tuple(nvd or [])

    async def fake_kev(*, path: Path, **_: Any) -> tuple[KevEntry, ...]:
        del path
        return tuple(kev or [])

    async def fake_mitre(*, path: Path, **_: Any) -> tuple[Any, ...]:
        del path
        return ()

    monkeypatch.setattr(agent_mod, "read_nvd_feed", fake_nvd)
    monkeypatch.setattr(agent_mod, "read_cisa_kev", fake_kev)
    monkeypatch.setattr(agent_mod, "read_mitre_attack", fake_mitre)


def _placeholder(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("placeholder", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Core assertion: ioc node must appear in the graph after run()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_kev_snapshot_persists_ioc_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() with a KEV feed entry must write an ``ioc`` node to the graph.

    The v0.1 IOC index derives ``IocType.CVE_ID`` entries from KEV records;
    each becomes an ``ioc`` entity with ``external_id = "cve_id:{cve_id}"``.
    """
    _patch_readers(monkeypatch, kev=[_kev(_CVE_ID)])

    async with in_memory_semantic_store() as store:
        await run(
            _contract(tmp_path),
            kev_snapshot=_placeholder(tmp_path / "kev.json"),
            semantic_store=store,
        )
        rows = await store.list_entities_by_type(tenant_id=_CUSTOMER_ID, entity_type="ioc")
        assert rows, (
            "expected >=1 'ioc' entity after run() with KEV feed, found none — "
            "_persist_to_semantic_store must call upsert_ioc for IOC entities"
        )
        external_ids = {row.external_id for row in rows}
        expected = f"cve_id:{_CVE_ID}"
        assert expected in external_ids, (
            f"expected ioc node external_id={expected!r}, got {external_ids!r}"
        )


@pytest.mark.asyncio
async def test_run_with_nvd_snapshot_persists_ioc_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() with an NVD feed entry must write an ``ioc`` node to the graph."""
    _patch_readers(monkeypatch, nvd=[_nvd(_CVE_ID)])

    async with in_memory_semantic_store() as store:
        await run(
            _contract(tmp_path),
            nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
            semantic_store=store,
        )
        rows = await store.list_entities_by_type(tenant_id=_CUSTOMER_ID, entity_type="ioc")
        assert rows, "expected >=1 'ioc' entity after run() with NVD feed, found none"
        external_ids = {row.external_id for row in rows}
        expected = f"cve_id:{_CVE_ID}"
        assert expected in external_ids, (
            f"expected ioc node external_id={expected!r}, got {external_ids!r}"
        )


@pytest.mark.asyncio
async def test_run_with_no_semantic_store_does_not_persist_ioc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """semantic_store=None must not write any ioc nodes (opt-in guard)."""
    _patch_readers(monkeypatch, kev=[_kev(_CVE_ID)])

    async with in_memory_semantic_store() as store:
        await run(
            _contract(tmp_path),
            kev_snapshot=_placeholder(tmp_path / "kev.json"),
            semantic_store=None,
        )
        rows = await store.list_entities_by_type(tenant_id=_CUSTOMER_ID, entity_type="ioc")
        assert not rows, f"expected no ioc entities when semantic_store=None, found {len(rows)}"


@pytest.mark.asyncio
async def test_ioc_node_external_id_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """IOC external_id must encode type and value as '{type}:{value}'."""
    cve_a = "CVE-2021-44228"
    cve_b = "CVE-2024-12345"
    _patch_readers(monkeypatch, kev=[_kev(cve_a)], nvd=[_nvd(cve_b)])

    async with in_memory_semantic_store() as store:
        await run(
            _contract(tmp_path),
            nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
            kev_snapshot=_placeholder(tmp_path / "kev.json"),
            semantic_store=store,
        )
        rows = await store.list_entities_by_type(tenant_id=_CUSTOMER_ID, entity_type="ioc")
        external_ids = {row.external_id for row in rows}
        # KEV takes priority on overlap; KEV entry → cve_a; NVD-only → cve_b
        assert f"cve_id:{cve_a}" in external_ids, f"missing KEV-derived IOC for {cve_a!r}"
        assert f"cve_id:{cve_b}" in external_ids, f"missing NVD-derived IOC for {cve_b!r}"
