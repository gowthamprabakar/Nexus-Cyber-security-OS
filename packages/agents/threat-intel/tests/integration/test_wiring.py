"""Fleet Test Level 1 — threat-intel (D.8) wiring smoke.

Tier A: the agent writes the graph + emits OCSF 2004 Detection Findings → the full §2.3
wiring assertions. Modeled on the runtime-threat (D.3) reference harness, adapted for D.8's
ingestion/correlation shape: findings come from correlating a feed (CISA KEV) against a
sibling D.1 vulnerability workspace, not from a single push reader.

L1 is SMOKE, not capability — proves plumbing only. Capability (precision/recall/FP) is L2.

Deviation (documented per swiss-bar #5/#12): D.8's ``kg_writer`` predates the ADR-018
``NodeCategory`` discipline and upserts **raw** ``entity_type`` strings (``"cve"`` / ``"ttp"``
/ ``"ioc"``) rather than ``NodeCategory`` members — see ``threat_intel/kg_writer.py`` and its
unit tests (``entity_type == "cve"`` etc.). No ``NodeCategory`` enum value equals those
strings, so the shared ``assert_entity_written`` / ``assert_no_entities`` /
``assert_two_tenant_disjoint`` helpers (which query by ``category.value``) cannot match D.8's
writes. We therefore assert the same invariants directly against the in-memory store using the
real entity-type strings the writer emits — exercising the genuine write path, not faking it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.memory.semantic import SemanticStore
from fleet_testkit import (
    assert_audit_chain,
    assert_ocsf_valid,
    in_memory_semantic_store,
    wiring_contract,
)
from shared.fabric.envelope import NexusEnvelope
from threat_intel import agent as agent_mod
from threat_intel.agent import run
from threat_intel.tools.cisa_kev import KevEntry
from threat_intel.tools.mitre_attack import TechniqueRecord
from threat_intel.tools.nvd_feed import NvdCveRecord
from vulnerability.schemas import AffectedPackage, VulnerabilityRecord
from vulnerability.schemas import Severity as VulnSeverity
from vulnerability.schemas import build_finding as build_vuln_finding

_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
# Feed readers (offline snapshots) + KG entity persistence are all the run() needs here.
_PERMITTED = ["read_nvd_feed", "read_cisa_kev", "read_mitre_attack"]
_OCSF_CLASS = 2004  # Detection Finding (threat_intel.schemas re-exports D.4's 2004)
_CVE_ID = "CVE-2021-44228"
# D.8 kg_writer's raw entity_type strings (see module docstring re: the NodeCategory deviation).
_KG_ENTITY_TYPES = ("cve", "ttp")


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
        references=(),
    )


def _technique() -> TechniqueRecord:
    return TechniqueRecord(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries abuse command interpreters.",
        tactics=["execution"],
        platforms=["Linux", "Windows", "macOS"],
        is_subtechnique=False,
        url="https://attack.mitre.org/techniques/T1059",
    )


def _patch_readers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the three offline feed readers with fixture-returning closures.

    Same pattern as ``test_agent_unit._patch_readers``: the readers are charter-registered
    and called via ``ctx.call_tool`` inside INGEST, so they must be patched at the agent
    module import level. NVD + KEV drive CVE entities; MITRE drives the TTP entity.
    """

    async def fake_nvd(*, path: Path, **_: Any) -> tuple[NvdCveRecord, ...]:
        del path
        return (_nvd(),)

    async def fake_kev(*, path: Path, **_: Any) -> tuple[KevEntry, ...]:
        del path
        return (_kev(),)

    async def fake_mitre(*, path: Path, **_: Any) -> tuple[TechniqueRecord, ...]:
        del path
        return (_technique(),)

    monkeypatch.setattr(agent_mod, "read_nvd_feed", fake_nvd)
    monkeypatch.setattr(agent_mod, "read_cisa_kev", fake_kev)
    monkeypatch.setattr(agent_mod, "read_mitre_attack", fake_mitre)


def _write_d1_findings_with_cve(workspace: Path, *, tenant_id: str, cve_id: str = _CVE_ID) -> None:
    """Seed a real D.1 vulnerability ``findings.json`` carrying ``cve_id`` (the correlation key).

    Uses vulnerability's own ``build_finding`` so the on-disk wire shape is the genuine one the
    CVE-KEV correlator reads.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    finding = build_vuln_finding(
        finding_id=f"VULN-log4j_core-{cve_id}",
        severity=VulnSeverity.CRITICAL,
        title="Log4Shell",
        description="x",
        affected_packages=[
            AffectedPackage(
                name="log4j-core",
                version="2.14.0",
                ecosystem="Maven",
                package_manager="maven",
            )
        ],
        vulnerabilities=[
            VulnerabilityRecord(
                cve_id=cve_id,
                title="x",
                cvss_v3_score=10.0,
                kev_flag=True,
                fix_available=True,
                fixed_version="2.16.0",
            )
        ],
        detected_at=_NOW,
        envelope=NexusEnvelope(
            correlation_id="00000000-0000-0000-0000-000000000001",
            tenant_id=tenant_id,
            agent_id="vulnerability",
            nlah_version="0.1.0",
            model_pin="deterministic",
            charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        ),
    )
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "vulnerability",
                "agent_version": "0.1.0",
                "customer_id": tenant_id,
                "run_id": "run_d1",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [finding.to_dict()],
            }
        ),
        encoding="utf-8",
    )


def _ti_contract(tmp_path: Path, **kwargs: Any) -> Any:
    """``wiring_contract`` with D.8's actual output artifacts.

    The shared builder declares ``required_outputs=["findings.json", "summary.md"]`` (the
    fleet-wide convention runtime-threat etc. follow), but D.8's ``run()`` writes
    ``findings.json`` + ``report.md`` — so ``ctx.assert_complete()`` would fail on the missing
    ``summary.md``. Override ``required_outputs`` to the artifacts D.8 genuinely emits; every
    other field stays the shared builder's.
    """
    contract = wiring_contract(tmp_path, **kwargs)
    return contract.model_copy(update={"required_outputs": ["findings.json", "report.md"]})


def _placeholder(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("placeholder", encoding="utf-8")
    return path


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


# NodeCategory-free store assertions — D.8's kg_writer emits raw entity_type strings (see
# module docstring). These mirror fleet_testkit's helpers but query the real strings.
async def _ids_for_types(
    store: SemanticStore, *, tenant_id: str, entity_types: Sequence[str]
) -> set[str]:
    out: set[str] = set()
    for entity_type in entity_types:
        rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=entity_type)
        out.update(row.entity_id for row in rows)
    return out


async def _assert_entity_type_written(
    store: SemanticStore, *, tenant_id: str, entity_type: str
) -> None:
    rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=entity_type)
    assert rows, (
        f"expected >=1 {entity_type!r} entity for tenant {tenant_id!r}, found none "
        f"(kg_writer did not write the expected node type)"
    )
    for row in rows:
        assert row.tenant_id == tenant_id, (
            f"entity {row.entity_id} carries tenant {row.tenant_id!r} != {tenant_id!r}"
        )


async def _assert_no_entity_types(
    store: SemanticStore, *, tenant_id: str, entity_types: Sequence[str]
) -> None:
    for entity_type in entity_types:
        rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=entity_type)
        assert not rows, (
            f"expected no {entity_type!r} entities for tenant {tenant_id!r}, found {len(rows)} "
            f"(a no-store / inert run must not write to the graph)"
        )


async def _assert_two_tenant_disjoint(
    store: SemanticStore, *, tenant_a: str, tenant_b: str, entity_types: Sequence[str]
) -> None:
    ids_a = await _ids_for_types(store, tenant_id=tenant_a, entity_types=entity_types)
    ids_b = await _ids_for_types(store, tenant_id=tenant_b, entity_types=entity_types)
    assert ids_a, f"tenant {tenant_a!r} wrote no entities — disjointness check is vacuous"
    assert ids_b, f"tenant {tenant_b!r} wrote no entities — disjointness check is vacuous"
    overlap = ids_a & ids_b
    assert not overlap, f"cross-tenant entity leak between {tenant_a!r} and {tenant_b!r}: {overlap}"


@pytest.mark.asyncio
async def test_wiring_threat_intel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid (+ cve_in_kev discriminator) ·
    cve/ttp entities written · audit chain hash-verifies · tenant isolation."""
    _patch_readers(monkeypatch)
    async with in_memory_semantic_store() as store:
        ws_a = tmp_path / "a"
        d1_a = ws_a / "d1"
        _write_d1_findings_with_cve(d1_a, tenant_id="tenant_a")
        contract_a = _ti_contract(
            ws_a,
            target_agent="threat_intel",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            cloud_api_calls=10,
        )
        report_a = await run(
            contract=contract_a,
            nvd_snapshot=_placeholder(ws_a / "nvd.json"),
            kev_snapshot=_placeholder(ws_a / "kev.json"),
            mitre_attack_snapshot=_placeholder(ws_a / "mitre.json"),
            vulnerability_workspace=d1_a,
            semantic_store=store,
        )

        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)
        # Per-agent discriminator (the class-specific check the shared helper leaves to harness)
        assert findings[0]["finding_info"]["types"][0] == "threat_intel_cve_in_kev_catalog"

        for entity_type in _KG_ENTITY_TYPES:
            await _assert_entity_type_written(store, tenant_id="tenant_a", entity_type=entity_type)
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation — distinct workspace, distinct delegation id, same shared store.
        ws_b = tmp_path / "b"
        d1_b = ws_b / "d1"
        _write_d1_findings_with_cve(d1_b, tenant_id="tenant_b")
        contract_b = _ti_contract(
            ws_b,
            target_agent="threat_intel",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            cloud_api_calls=10,
        )
        await run(
            contract=contract_b,
            nvd_snapshot=_placeholder(ws_b / "nvd.json"),
            kev_snapshot=_placeholder(ws_b / "kev.json"),
            mitre_attack_snapshot=_placeholder(ws_b / "mitre.json"),
            vulnerability_workspace=d1_b,
            semantic_store=store,
        )
        await _assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", entity_types=_KG_ENTITY_TYPES
        )


@pytest.mark.asyncio
async def test_wiring_threat_intel_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _patch_readers(monkeypatch)
    async with in_memory_semantic_store() as store:
        d1 = tmp_path / "d1"
        _write_d1_findings_with_cve(d1, tenant_id="t_off")
        contract = _ti_contract(
            tmp_path,
            target_agent="threat_intel",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            cloud_api_calls=10,
        )
        report = await run(
            contract=contract,
            nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
            kev_snapshot=_placeholder(tmp_path / "kev.json"),
            mitre_attack_snapshot=_placeholder(tmp_path / "mitre.json"),
            vulnerability_workspace=d1,
            semantic_store=None,
        )
        assert report.total >= 1
        await _assert_no_entity_types(store, tenant_id="t_off", entity_types=_KG_ENTITY_TYPES)
