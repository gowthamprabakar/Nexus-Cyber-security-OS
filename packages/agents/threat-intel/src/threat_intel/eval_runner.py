"""`ThreatIntelEvalRunner` — the canonical `EvalRunner` for D.8.

Mirrors D.4's
[`eval_runner.py`](../../../network-threat/src/network_threat/eval_runner.py)
shape — patches the three feed-reader tools at the agent module's
import scope, synthesises any required D.1 / D.4 / D.3 sibling-
workspace ``findings.json`` files from the case fixture, builds an
``ExecutionContract`` rooted at the suite-supplied workspace, calls
``threat_intel.agent.run``, then compares the resulting
``FindingsReport`` to ``case.expected``.

Fixture keys (under ``fixture``):

Feed snapshots (synthesizer directives -- the runner expands these
into NvdCveRecord / KevEntry / TechniqueRecord tuples so the YAML
stays compact):

  - ``kev_entries: list[dict]`` -- one KevEntry per entry (cve_id,
    vendor_project, product, vulnerability_name, date_added (str),
    due_date (str|None), known_ransomware_campaign_use bool).
  - ``nvd_cves: list[dict]`` -- one NvdCveRecord per entry (cve_id,
    description, published (str), last_modified (str|None),
    cvss_v3_score, cvss_v3_severity).
  - ``mitre_techniques: list[dict]`` -- one TechniqueRecord per
    entry (technique_id, name, tactics, platforms).

Sibling-workspace synthesizer directives (the runner writes
``findings.json`` files into ephemeral sub-paths):

  - ``d1_findings_with_cves: list[dict]`` -- one VulnerabilityFinding
    per entry (cve_id, package_name, package_version, ecosystem).
  - ``d4_suricata_with_cves: list[dict]`` -- one Suricata-shaped
    NetworkFinding per entry (signature, src_ip, dst_ip,
    signature_id).
  - ``malformed_d4_findings_json: bool`` -- if true, the D.4
    workspace's findings.json is intentionally malformed so the
    correlator's forgiving-read posture is exercised.

Comparison shape (under ``expected``):

  - ``finding_count: int``
  - ``by_severity: {sev: int}`` -- checked when present.
  - ``by_finding_type: {ft: int}`` -- checked when present.

Registered via ``pyproject.toml`` ``[project.entry-points.
"nexus_eval_runners"]`` so ``eval-framework run --runner
threat_intel`` resolves it.
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from network_threat.schemas import AffectedNetwork
from network_threat.schemas import FindingType as NetFindingType
from network_threat.schemas import Severity as NetSeverity
from network_threat.schemas import build_finding as build_net_finding
from shared.fabric.envelope import NexusEnvelope
from vulnerability.schemas import AffectedPackage, VulnerabilityRecord
from vulnerability.schemas import Severity as VulnSeverity
from vulnerability.schemas import build_finding as build_vuln_finding

from threat_intel import agent as agent_mod
from threat_intel.schemas import (
    FindingsReport,
    ThreatIntelFindingType,
)
from threat_intel.tools.cisa_kev import KevEntry
from threat_intel.tools.mitre_attack import TechniqueRecord
from threat_intel.tools.nvd_feed import NvdCveRecord


class ThreatIntelEvalRunner:
    """Reference ``EvalRunner`` for the Threat Intel Agent (D.8)."""

    @property
    def agent_name(self) -> str:
        return "threat_intel"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report = await _run_case_async(case, contract, llm_provider=llm_provider)

        passed, failure_reason = _evaluate(case, report)
        actuals: dict[str, Any] = {
            "finding_count": report.total,
            "by_severity": report.count_by_severity(),
            "by_finding_type": _count_by_finding_type(report),
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> FindingsReport:
    fixture = case.fixture

    nvd_records = tuple(_parse_nvd(n) for n in fixture.get("nvd_cves", []) or [])
    kev_entries = tuple(_parse_kev(k) for k in fixture.get("kev_entries", []) or [])
    techniques = tuple(_parse_technique(t) for t in fixture.get("mitre_techniques", []) or [])

    async def fake_nvd(**_: Any) -> tuple[NvdCveRecord, ...]:
        return nvd_records

    async def fake_kev(**_: Any) -> tuple[KevEntry, ...]:
        return kev_entries

    async def fake_mitre(**_: Any) -> tuple[TechniqueRecord, ...]:
        return techniques

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    nvd_path, kev_path, mitre_path = _placeholder_paths(workspace)
    nvd_snapshot: Path | None = nvd_path if nvd_records else None
    kev_snapshot: Path | None = kev_path if kev_entries else None
    mitre_snapshot: Path | None = mitre_path if techniques else None

    d1_ws = _write_d1_workspace(workspace, fixture)
    d4_ws = _write_d4_workspace(workspace, fixture)

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_nvd_feed", fake_nvd))
        stack.enter_context(patch.object(agent_mod, "read_cisa_kev", fake_kev))
        stack.enter_context(patch.object(agent_mod, "read_mitre_attack", fake_mitre))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            nvd_snapshot=nvd_snapshot,
            kev_snapshot=kev_snapshot,
            mitre_attack_snapshot=mitre_snapshot,
            vulnerability_workspace=d1_ws,
            network_threat_workspace=d4_ws,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="threat_intel",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_nvd_feed", "read_cisa_kev", "read_mitre_attack"],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _placeholder_paths(workspace: Path) -> tuple[Path, Path, Path]:
    """Write placeholder files so the readers (patched away) still see a Path."""
    nvd = workspace / "_fixture_nvd.json"
    kev = workspace / "_fixture_kev.json"
    mitre = workspace / "_fixture_mitre.json"
    for p in (nvd, kev, mitre):
        p.write_text("placeholder\n")
    return nvd, kev, mitre


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------


def _evaluate(case: EvalCase, report: FindingsReport) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()
    type_counts = _count_by_finding_type(report)

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    expected_types = case.expected.get("by_finding_type") or {}
    for ft, want in expected_types.items():
        actual = type_counts.get(str(ft), 0)
        if actual != int(want):
            return False, f"finding_type '{ft}' expected {want}, got {actual}"

    return True, None


def _count_by_finding_type(report: FindingsReport) -> dict[str, int]:
    counts: dict[str, int] = {ft.value: 0 for ft in ThreatIntelFindingType}
    for raw in report.findings:
        types = raw.get("finding_info", {}).get("types") or []
        if isinstance(types, list) and types and isinstance(types[0], str):
            counts[types[0]] = counts.get(types[0], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Feed fixture parsers
# ---------------------------------------------------------------------------


def _parse_nvd(raw: dict[str, Any]) -> NvdCveRecord:
    published = _parse_dt(raw.get("published")) or datetime(2024, 1, 1, tzinfo=UTC)
    last_modified = _parse_dt(raw.get("last_modified")) or published
    return NvdCveRecord(
        cve_id=str(raw.get("cve_id", "")),
        description=str(raw.get("description", "")),
        published=published,
        last_modified=last_modified,
        vuln_status=str(raw.get("vuln_status", "")),
        cvss_v3_score=raw.get("cvss_v3_score"),
        cvss_v3_severity=raw.get("cvss_v3_severity"),
        references=[str(r) for r in (raw.get("references") or [])],
    )


def _parse_kev(raw: dict[str, Any]) -> KevEntry:
    return KevEntry(
        cve_id=str(raw.get("cve_id", "")),
        vendor_project=str(raw.get("vendor_project", "")),
        product=str(raw.get("product", "")),
        vulnerability_name=str(raw.get("vulnerability_name", "")),
        date_added=_parse_date_required(raw.get("date_added")),
        short_description=str(raw.get("short_description", "")),
        required_action=str(raw.get("required_action", "Apply updates.")),
        due_date=_parse_date_optional(raw.get("due_date")),
        known_ransomware_campaign_use=bool(raw.get("known_ransomware_campaign_use", False)),
        notes=str(raw.get("notes", "")),
        cwes=list(raw.get("cwes", []) or []),
    )


def _parse_technique(raw: dict[str, Any]) -> TechniqueRecord:
    return TechniqueRecord(
        technique_id=str(raw.get("technique_id", "")),
        name=str(raw.get("name", "")),
        description=str(raw.get("description", "")),
        tactics=list(raw.get("tactics", []) or []),
        platforms=list(raw.get("platforms", []) or []),
        is_subtechnique=bool(raw.get("is_subtechnique", False)),
        url=str(raw.get("url", "")),
    )


# ---------------------------------------------------------------------------
# Sibling-workspace synthesisers (D.1 / D.4)
# ---------------------------------------------------------------------------


def _eval_envelope(agent_id: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-000000000eee",
        tenant_id="cust_eval",
        agent_id=agent_id,
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _write_d1_workspace(workspace: Path, fixture: dict[str, Any]) -> Path | None:
    entries = fixture.get("d1_findings_with_cves") or []
    if not entries:
        return None
    d1_ws = workspace / "_d1"
    d1_ws.mkdir(parents=True, exist_ok=True)
    findings: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get("cve_id", ""))
        if not cve_id:
            continue
        finding = build_vuln_finding(
            finding_id=f"VULN-pkg_eval-{cve_id}",
            severity=VulnSeverity.CRITICAL,
            title=f"Vulnerability {cve_id}",
            description="eval fixture",
            affected_packages=[
                AffectedPackage(
                    name=str(entry.get("package_name", "pkg")),
                    version=str(entry.get("package_version", "1.0.0")),
                    ecosystem=str(entry.get("ecosystem", "PyPI")),
                    package_manager=str(entry.get("package_manager", "pip")),
                )
            ],
            vulnerabilities=[
                VulnerabilityRecord(
                    cve_id=cve_id,
                    title=f"{cve_id} detail",
                    cvss_v3_score=10.0,
                    kev_flag=True,
                    fix_available=True,
                    fixed_version="9.9.9",
                )
            ],
            detected_at=datetime.now(UTC),
            envelope=_eval_envelope("vulnerability"),
        )
        findings.append(finding.to_dict())
    (d1_ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "vulnerability",
                "agent_version": "0.1.0",
                "customer_id": "cust_eval",
                "run_id": "run_eval_d1",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    return d1_ws


def _write_d4_workspace(workspace: Path, fixture: dict[str, Any]) -> Path | None:
    entries = fixture.get("d4_suricata_with_cves") or []
    malformed = bool(fixture.get("malformed_d4_findings_json", False))
    if not entries and not malformed:
        return None
    d4_ws = workspace / "_d4"
    d4_ws.mkdir(parents=True, exist_ok=True)
    if malformed:
        (d4_ws / "findings.json").write_text("{not-json", encoding="utf-8")
        return d4_ws

    findings: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        signature = str(entry.get("signature", ""))
        src_ip = str(entry.get("src_ip", "10.0.1.42"))
        dst_ip = str(entry.get("dst_ip", "203.0.113.55"))
        sig_id = int(entry.get("signature_id", 2034567 + idx))
        finding = build_net_finding(
            finding_id=f"NETWORK-SURICATA-10001042-{idx:03d}-sig",
            finding_type=NetFindingType.SURICATA,
            severity=NetSeverity.HIGH,
            title="Suricata alert (eval)",
            description=signature,
            affected_networks=[AffectedNetwork(src_ip=src_ip, dst_ip=dst_ip)],
            evidence={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_id": sig_id,
                "signature": signature,
            },
            detected_at=datetime.now(UTC),
            envelope=_eval_envelope("network_threat"),
            detector_id="suricata:eval",
        )
        findings.append(finding.to_dict())
    (d4_ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "network_threat",
                "agent_version": "0.1.0",
                "customer_id": "cust_eval",
                "run_id": "run_eval_d4",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    return d4_ws


# ---------------------------------------------------------------------------
# Small parse helpers
# ---------------------------------------------------------------------------


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _parse_date_required(value: Any) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str) and value:
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    return date(2024, 1, 1)


def _parse_date_optional(value: Any) -> date | None:
    if value is None:
        return None
    return _parse_date_required(value)


__all__ = ["ThreatIntelEvalRunner"]
