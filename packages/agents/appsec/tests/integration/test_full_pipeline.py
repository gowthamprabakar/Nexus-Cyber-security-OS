"""B-1 PR9 — D.14 AppSec full-pipeline + multi-tenant integration tests.

The per-scanner unit tests (``test_agent_unit.py``) each stub two scanners and
exercise one. This suite closes two cycle-level gaps:

1. **Full pipeline in one run** — all three scanners (Checkov IaC + gitleaks
   secrets + Semgrep SAST) fire on the same repo in a single ``run()``, and the
   run emits the complete artifact set: ``findings.json`` carrying both OCSF 2003
   discriminators (IaC + SAST) *and* ``code_secrets.json`` carrying the redacted
   secrets-in-code handoff (ADR-015 → DSPM). Proves the scanners compose, not just
   work in isolation.

2. **Multi-tenant isolation** — two tenants scanned into separate workspaces tag
   their OCSF findings with their own ``metadata.tenant_uid`` (= ``customer_id``)
   and never leak the other tenant's id. The OCSF emitter is the tenant boundary
   the posture fleet relies on.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from appsec import agent as agent_mod
from appsec.agent import run
from appsec.schemas import RepoRef
from appsec.tools.checkov_runner import CheckovResult
from appsec.tools.gitleaks_runner import GitleaksResult
from appsec.tools.scm_connector import StaticScmConnector
from appsec.tools.semgrep_runner import SemgrepResult
from charter.contract import BudgetSpec, ExecutionContract

pytestmark = pytest.mark.asyncio

# AWS docs example key — a deterministic test fixture, never a live credential.
_PLAINTEXT_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105


def _contract(*, customer_id: str, workspace: Path, persistent: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="appsec",
        customer_id=customer_id,
        task="Scan source repositories",
        required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=[
            "discover_repositories",
            "run_checkov",
            "run_gitleaks",
            "run_semgrep",
            "clone_repository",
        ],
        completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(workspace),
        persistent_root=str(persistent),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _wire_all_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub all three scanners: one IaC fail + one secret + one SAST hit."""

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
                    "Secret": _PLAINTEXT_SECRET,
                    "Match": f"KEY={_PLAINTEXT_SECRET}",
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
                        "extra": {
                            "message": "Detected use of exec()",
                            "severity": "ERROR",
                        },
                    }
                ]
            }
        )

    monkeypatch.setattr(agent_mod, "run_checkov", fake_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", fake_gitleaks)
    monkeypatch.setattr(agent_mod, "run_semgrep", fake_semgrep)


def _local_repo(tmp_path: Path) -> RepoRef:
    return RepoRef(
        host="github",
        owner="acme",
        name="api",
        clone_url="https://github.com/acme/api.git",
        local_path=str(tmp_path / "checkout"),
    )


async def test_full_pipeline_emits_iac_sast_and_secret_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_all_scanners(monkeypatch)
    ws = tmp_path / "ws"
    await run(
        _contract(customer_id="cust_a", workspace=ws, persistent=tmp_path / "p"),
        scm_connector=StaticScmConnector([_local_repo(tmp_path)]),
    )

    findings = json.loads((ws / "findings.json").read_text())["findings"]
    # IaC + SAST both surface as OCSF 2003, distinguished by discriminator.
    assert all(f["class_uid"] == 2003 for f in findings)
    types = sorted(f["finding_info"]["types"][0] for f in findings)
    assert types == ["appsec_iac_misconfiguration", "appsec_sast_finding"]

    # gitleaks → redacted code_secrets.json handoff (ADR-015 → DSPM), plaintext absent.
    secrets_text = (ws / "code_secrets.json").read_text()
    assert _PLAINTEXT_SECRET not in secrets_text
    secrets = json.loads(secrets_text)
    assert secrets["secrets"][0]["rule_id"] == "aws-access-token"


async def test_multi_tenant_findings_carry_own_tenant_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_all_scanners(monkeypatch)

    tenant_uids: dict[str, set[str]] = {}
    for cust in ("tenant_alpha", "tenant_beta"):
        ws = tmp_path / cust / "ws"
        await run(
            _contract(customer_id=cust, workspace=ws, persistent=tmp_path / cust / "p"),
            scm_connector=StaticScmConnector([_local_repo(tmp_path / cust)]),
        )
        findings = json.loads((ws / "findings.json").read_text())["findings"]
        assert findings, "each tenant produced findings"
        tenant_uids[cust] = {f["metadata"]["tenant_uid"] for f in findings}

    # Each tenant's findings carry only its own tenant_uid — no cross-tenant leak.
    assert tenant_uids["tenant_alpha"] == {"tenant_alpha"}
    assert tenant_uids["tenant_beta"] == {"tenant_beta"}
