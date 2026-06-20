"""Fleet Test Level 1 — appsec (D.14) wiring smoke.

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions, copying
the cloud-posture / runtime-threat reference shape. appsec emits **bare** OCSF 2003 into
``findings.json`` (the file is ``{"findings": [...]}``; each element is a bare OCSF event with
no ``nexus_envelope`` wrapper — ``assert_ocsf_valid`` handles bare findings).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). Capability (precision/recall) is L2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from appsec import agent as agent_mod
from appsec.agent import run
from appsec.schemas import RepoRef
from appsec.tools.checkov_runner import CheckovResult
from appsec.tools.gitleaks_runner import GitleaksResult
from appsec.tools.scm_connector import StaticScmConnector
from appsec.tools.semgrep_runner import SemgrepResult
from charter.memory.graph_types import NodeCategory
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)

_PERMITTED = [
    "discover_repositories",
    "run_checkov",
    "run_gitleaks",
    "run_semgrep",
    "clone_repository",
]
# appsec writes CODE_REPOSITORY per discovered repo + IAC_ARTIFACT per IaC finding.
_CATEGORIES = (NodeCategory.CODE_REPOSITORY, NodeCategory.IAC_ARTIFACT)
_OCSF_CLASS = 2003  # Compliance Finding (appsec.ocsf.emission)


def _wire_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub all three scanners with one IaC fail + one secret + one SAST hit (the unit-test
    fakes, which mirror real Checkov/gitleaks/Semgrep payload shapes — swiss-bar #3)."""

    async def fake_checkov(repo_path: str, **_: object) -> CheckovResult:
        return CheckovResult(
            payload={
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 public ACL",
                            "file_path": "/main.tf",
                            "file_line_range": [1, 5],
                            "resource": "aws_s3_bucket.x",
                            "severity": "HIGH",
                        }
                    ]
                }
            }
        )

    async def fake_gitleaks(repo_path: str, **_: object) -> GitleaksResult:
        return GitleaksResult(
            payload=[
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS Access Token",
                    "File": "src/config.py",
                    "StartLine": 12,
                    "EndLine": 12,
                    "Secret": "AKIAIOSFODNN7EXAMPLE",  # AWS docs example key, not a live cred
                    "Match": "KEY=AKIAIOSFODNN7EXAMPLE",
                }
            ]
        )

    async def fake_semgrep(repo_path: str, **_: object) -> SemgrepResult:
        return SemgrepResult(
            payload={
                "results": [
                    {
                        "check_id": "python.lang.security.audit.dangerous-exec",
                        "path": "src/app.py",
                        "start": {"line": 42},
                        "extra": {"message": "Detected use of exec()", "severity": "ERROR"},
                    }
                ]
            }
        )

    monkeypatch.setattr(agent_mod, "run_checkov", fake_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", fake_gitleaks)
    monkeypatch.setattr(agent_mod, "run_semgrep", fake_semgrep)


def _local_repo(root: Path) -> RepoRef:
    return RepoRef(
        host="github",
        owner="acme",
        name="api",
        clone_url="https://github.com/acme/api.git",
        local_path=str(root / "checkout"),
    )


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_appsec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid (IaC + SAST discriminators) ·
    CODE_REPOSITORY + IAC_ARTIFACT written · audit chain hash-verifies · tenant isolation."""
    _wire_scanners(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a,
            target_agent="appsec",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
            completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        )
        inventory_a = await run(
            contract=contract_a,
            scm_connector=StaticScmConnector([_local_repo(ws_a)]),
            semantic_store=store,
        )

        # run-completes + produced findings
        assert inventory_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CODE_REPOSITORY
        )
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.IAC_ARTIFACT)

        # audit chain hash-verifies (Charter writes audit.jsonl in the workspace)
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="appsec",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
            completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        )
        await run(
            contract=contract_b,
            scm_connector=StaticScmConnector([_local_repo(ws_b)]),
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_appsec_inert_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _wire_scanners(monkeypatch)
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path,
            target_agent="appsec",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
            completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        )
        inventory = await run(
            contract=contract,
            scm_connector=StaticScmConnector([_local_repo(tmp_path)]),
            semantic_store=None,
        )
        assert inventory.total >= 1
        findings = _findings(tmp_path / "ws")
        assert findings, "no findings emitted offline"
        # The injected store (unused by the run) stays empty — inert offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
