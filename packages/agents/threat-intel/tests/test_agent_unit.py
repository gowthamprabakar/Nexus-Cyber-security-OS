"""Unit tests — D.8 Threat Intel agent driver (Task 12).

All three feed readers are mocked at the agent module's import level
(monkeypatching ``agent.read_nvd_feed`` etc.). The test surface is the
agent's wiring of charter + readers + correlators + scorer +
summarizer, not the readers' parsing behaviour (those have their own
test files).

Sibling-workspace fixtures (D.1, D.4, D.3 findings.json) are built
using each sibling's own ``build_finding`` so the wire shape is the
real one.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from network_threat.schemas import AffectedNetwork
from network_threat.schemas import FindingType as NetFindingType
from network_threat.schemas import Severity as NetSeverity
from network_threat.schemas import build_finding as build_net_finding
from runtime_threat.schemas import AffectedHost
from runtime_threat.schemas import FindingType as RtFindingType
from runtime_threat.schemas import Severity as RtSeverity
from runtime_threat.schemas import build_finding as build_rt_finding
from shared.fabric.envelope import NexusEnvelope
from threat_intel import agent as agent_mod
from threat_intel.agent import build_registry, run
from threat_intel.tools.cisa_kev import KevEntry
from threat_intel.tools.mitre_attack import TechniqueRecord
from threat_intel.tools.nvd_feed import NvdCveRecord
from vulnerability.schemas import AffectedPackage, VulnerabilityRecord
from vulnerability.schemas import Severity as VulnSeverity
from vulnerability.schemas import build_finding as build_vuln_finding

NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="threat_intel",
        customer_id="acme",
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
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _kev(cve_id: str = "CVE-2021-44228") -> KevEntry:
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


def _nvd(cve_id: str = "CVE-2021-44228") -> NvdCveRecord:
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


def _patch_readers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    nvd: list[NvdCveRecord] | None = None,
    kev: list[KevEntry] | None = None,
    mitre: list[TechniqueRecord] | None = None,
) -> None:
    """Replace the three reader functions with closures returning fixtures."""

    async def fake_nvd(*, path: Path, **_: Any) -> tuple[NvdCveRecord, ...]:
        del path
        return tuple(nvd or [])

    async def fake_kev(*, path: Path, **_: Any) -> tuple[KevEntry, ...]:
        del path
        return tuple(kev or [])

    async def fake_mitre(*, path: Path, **_: Any) -> tuple[TechniqueRecord, ...]:
        del path
        return tuple(mitre or [])

    monkeypatch.setattr(agent_mod, "read_nvd_feed", fake_nvd)
    monkeypatch.setattr(agent_mod, "read_cisa_kev", fake_kev)
    monkeypatch.setattr(agent_mod, "read_mitre_attack", fake_mitre)


def _write_d1_findings_with_cve(workspace: Path, cve_id: str = "CVE-2021-44228") -> None:
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
        detected_at=NOW,
        envelope=NexusEnvelope(
            correlation_id="00000000-0000-0000-0000-000000000001",
            tenant_id="acme",
            agent_id="vulnerability",
            nlah_version="0.1.0",
            model_pin="deterministic",
            charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        ),
    )
    payload = finding.to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "vulnerability",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "run_d1",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )


def _write_d4_findings_with_signature(workspace: Path, signature: str) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    finding = build_net_finding(
        finding_id="NETWORK-SURICATA-10001042-001-sig",
        finding_type=NetFindingType.SURICATA,
        severity=NetSeverity.HIGH,
        title="Suricata alert",
        description=signature,
        affected_networks=[AffectedNetwork(src_ip="10.0.1.42", dst_ip="203.0.113.55")],
        evidence={
            "src_ip": "10.0.1.42",
            "dst_ip": "203.0.113.55",
            "signature_id": 2034567,
            "signature": signature,
        },
        detected_at=NOW,
        envelope=NexusEnvelope(
            correlation_id="00000000-0000-0000-0000-000000000002",
            tenant_id="acme",
            agent_id="network_threat",
            nlah_version="0.1.0",
            model_pin="deterministic",
            charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        ),
        detector_id="suricata:2024-001",
    )
    payload = finding.to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "network_threat",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "run_d4",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )


def _write_d3_findings_with_remote_ip(workspace: Path, remote_ip: str) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    finding = build_rt_finding(
        finding_id="RUNTIME-NETWORK-ABC123-001-egress",
        finding_type=RtFindingType.NETWORK,
        severity=RtSeverity.HIGH,
        title="Outbound to known-bad IP",
        description="x",
        affected_hosts=[
            AffectedHost(
                hostname="ip-10-0-1-42",
                host_id="abc123def456",
                image_ref="nginx:1.27",
                namespace="prod",
                ip_addresses=("10.0.1.42",),
            )
        ],
        evidence={"remote_ip": remote_ip, "remote_port": 443, "direction": "outbound"},
        detected_at=NOW,
        envelope=NexusEnvelope(
            correlation_id="00000000-0000-0000-0000-000000000003",
            tenant_id="acme",
            agent_id="runtime_threat",
            nlah_version="0.1.0",
            model_pin="deterministic",
            charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        ),
        rule_id="nx-egress-policy",
    )
    payload = finding.to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "runtime_threat",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "run_d3",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )


def _placeholder(path: Path) -> Path:
    path.write_text("placeholder", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_build_registry_includes_three_feed_readers() -> None:
    reg = build_registry()
    known = reg.known_tools()
    assert "read_nvd_feed" in known
    assert "read_cisa_kev" in known
    assert "read_mitre_attack" in known


# ---------------------------------------------------------------------------
# Empty path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_no_feeds_or_workspaces_yields_empty_report(
    tmp_path: Path,
) -> None:
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid_and_attribution_in_report(
    tmp_path: Path,
) -> None:
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "threat_intel"
    assert payload["customer_id"] == "acme"
    assert payload["findings"] == []
    md = (tmp_path / "ws" / "report.md").read_text()
    assert "MITRE ATT&CK" in md
    assert "CC-BY-4.0" in md


# ---------------------------------------------------------------------------
# CVE x D.1 correlation through the full pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kev_feed_plus_d1_workspace_emits_cve_kev_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, kev=[_kev("CVE-2021-44228")])
    d1_ws = tmp_path / "d1"
    _write_d1_findings_with_cve(d1_ws, "CVE-2021-44228")

    report = await run(
        _contract(tmp_path),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        vulnerability_workspace=d1_ws,
    )
    assert report.total == 1
    finding = report.findings[0]
    assert finding["finding_info"]["types"][0] == "threat_intel_cve_in_kev_catalog"
    assert finding["class_uid"] == 2004
    assert finding["severity"] == "Critical"


@pytest.mark.asyncio
async def test_kev_without_matching_d1_emits_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, kev=[_kev("CVE-2021-44228")])
    d1_ws = tmp_path / "d1"
    _write_d1_findings_with_cve(d1_ws, "CVE-2024-99999")

    report = await run(
        _contract(tmp_path),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        vulnerability_workspace=d1_ws,
    )
    assert report.total == 0


# ---------------------------------------------------------------------------
# IOC x D.4 (Suricata CVE-ID) correlation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_plus_d4_suricata_cve_signature_emits_ioc_net_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, nvd=[_nvd("CVE-2021-44228")])
    d4_ws = tmp_path / "d4"
    _write_d4_findings_with_signature(d4_ws, "ET EXPLOIT Possible CVE-2021-44228 exploit attempt")

    report = await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        network_threat_workspace=d4_ws,
    )
    assert report.total == 1
    finding = report.findings[0]
    assert finding["finding_info"]["types"][0] == "threat_intel_ioc_match_network"


# ---------------------------------------------------------------------------
# IOC x D.3 correlation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_cve_plus_d3_does_not_match_remote_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.1 NVD-derived IOC index only carries CVE_ID entries; a D.3
    NETWORK finding's remote_ip will NOT hit the index by itself."""
    _patch_readers(monkeypatch, nvd=[_nvd("CVE-2021-44228")])
    d3_ws = tmp_path / "d3"
    _write_d3_findings_with_remote_ip(d3_ws, "203.0.113.55")

    report = await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        runtime_threat_workspace=d3_ws,
    )
    assert report.total == 0


# ---------------------------------------------------------------------------
# Scoring: re-stamps from correlator severities to canonical
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cve_kev_severity_is_critical_via_scorer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, kev=[_kev()])
    d1_ws = tmp_path / "d1"
    _write_d1_findings_with_cve(d1_ws)

    report = await run(
        _contract(tmp_path),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        vulnerability_workspace=d1_ws,
    )
    assert report.findings[0]["severity_id"] == 5  # CRITICAL


# ---------------------------------------------------------------------------
# Summarizer wiring: attribution footer + sections appear
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_md_includes_cve_kev_section_when_kev_finding_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, kev=[_kev()])
    d1_ws = tmp_path / "d1"
    _write_d1_findings_with_cve(d1_ws)

    await run(
        _contract(tmp_path),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        vulnerability_workspace=d1_ws,
    )
    md = (tmp_path / "ws" / "report.md").read_text()
    assert "## CVE in CISA KEV" in md
    assert "## Attribution" in md


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_jsonl_records_tool_calls_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, nvd=[_nvd()], kev=[_kev()], mitre=[_technique()])
    await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        mitre_attack_snapshot=_placeholder(tmp_path / "mitre.json"),
    )
    audit_path = tmp_path / "ws" / "audit.jsonl"
    assert audit_path.is_file()
    events = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    actions = [e.get("action") for e in events]
    # 3 tool calls + 2 output writes are the minimum we expect.
    assert actions.count("tool_call") == 3
    assert actions.count("output_written") == 2


# ---------------------------------------------------------------------------
# SemanticStore opt-in
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_no_semantic_store_skips_kg_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """semantic_store=None default must not touch a substrate."""
    _patch_readers(monkeypatch, nvd=[_nvd()])
    report = await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        semantic_store=None,
    )
    # report still emits cleanly without KG; total = 0 (no sibling workspace).
    assert report.total == 0


@pytest.mark.asyncio
async def test_run_with_semantic_store_calls_upsert_entity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a SemanticStore is passed, KG writes happen for NVD CVE +
    KEV CVE + ATT&CK technique entities."""
    _patch_readers(
        monkeypatch,
        nvd=[_nvd("CVE-2021-44228")],
        kev=[_kev("CVE-2024-12345")],  # distinct so we get 2 CVE entities
        mitre=[_technique()],
    )

    upserts: list[dict[str, Any]] = []

    async def fake_upsert_entity(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        upserts.append(
            {
                "tenant_id": tenant_id,
                "entity_type": entity_type,
                "external_id": external_id,
            }
        )
        return f"ent_{len(upserts)}"

    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.side_effect = fake_upsert_entity

    await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        mitre_attack_snapshot=_placeholder(tmp_path / "mitre.json"),
        semantic_store=store,
    )

    entity_types = [u["entity_type"] for u in upserts]
    # 1 CVE from NVD + 1 CVE from KEV (different IDs) + 1 TTP from ATT&CK = 3
    assert entity_types.count("cve") == 2
    assert entity_types.count("ttp") == 1
    assert all(u["tenant_id"] == "acme" for u in upserts)


# ---------------------------------------------------------------------------
# All three correlators wired together
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_three_correlators_fire_when_all_inputs_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(
        monkeypatch,
        nvd=[_nvd("CVE-2021-44228")],
        kev=[_kev("CVE-2021-44228")],
        mitre=[_technique()],
    )

    d1_ws = tmp_path / "d1"
    d4_ws = tmp_path / "d4"
    _write_d1_findings_with_cve(d1_ws, "CVE-2021-44228")
    _write_d4_findings_with_signature(d4_ws, "ET EXPLOIT CVE-2021-44228 attempt")

    report = await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
        mitre_attack_snapshot=_placeholder(tmp_path / "mitre.json"),
        vulnerability_workspace=d1_ws,
        network_threat_workspace=d4_ws,
    )
    types = [f["finding_info"]["types"][0] for f in report.findings]
    # Expect: 1 CVE_KEV + 1 IOC_NET (CVE-ID match in Suricata signature).
    assert "threat_intel_cve_in_kev_catalog" in types
    assert "threat_intel_ioc_match_network" in types
    assert report.total == 2


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_d1_workspace_does_not_break_other_correlators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even with no D.1 workspace, IOC x D.4 still fires."""
    _patch_readers(monkeypatch, nvd=[_nvd("CVE-2021-44228")])
    d4_ws = tmp_path / "d4"
    _write_d4_findings_with_signature(d4_ws, "ET EXPLOIT CVE-2021-44228 attempt")

    report = await run(
        _contract(tmp_path),
        nvd_snapshot=_placeholder(tmp_path / "nvd.json"),
        network_threat_workspace=d4_ws,
        # vulnerability_workspace deliberately not set
    )
    assert report.total == 1
    assert report.findings[0]["finding_info"]["types"][0] == "threat_intel_ioc_match_network"


@pytest.mark.asyncio
async def test_report_metadata_carries_customer_and_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_readers(monkeypatch, kev=[_kev()])
    report = await run(
        _contract(tmp_path),
        kev_snapshot=_placeholder(tmp_path / "kev.json"),
    )
    assert report.customer_id == "acme"
    assert report.run_id == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    assert report.agent == "threat_intel"


# Type-narrowing helper so mypy doesn't flag Sequence[Any] later. Suppresses
# unused-import warning while keeping the runtime-threat schema imports.
_ = Sequence
