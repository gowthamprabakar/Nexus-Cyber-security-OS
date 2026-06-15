"""``AppSecEvalRunner`` — the canonical ``EvalRunner`` for the D.14 AppSec agent.

B-1 PR10. Brings D.14 to fleet eval parity (mirrors the vulnerability /
cloud-posture runners) so the agent can participate in the meta-harness eval +
skill-improvement loop.

- Patches the three scanner wrappers (``run_checkov`` / ``run_gitleaks`` /
  ``run_semgrep``) per ``case.fixture`` for deterministic replay.
- Builds an ``ExecutionContract`` rooted at the suite-supplied ``workspace`` and
  runs ``appsec.agent.run`` against a single local-path repo.
- Reads the written artifacts (``findings.json`` OCSF 2003 + ``code_secrets.json``
  redacted handoff) and compares to ``case.expected``. ``run()`` returns the
  ``RepoInventory``, so findings are read back from the workspace.

Fixture keys (under ``fixture``):
- ``checkov_failed_checks: list[dict]`` — Checkov ``results.failed_checks`` rows.
- ``gitleaks_hits: list[dict]`` — gitleaks report rows (redacted on handoff).
- ``semgrep_results: list[dict]`` — Semgrep ``results`` rows.
- ``repo_slug: str`` — optional; default ``github/acme/api``.

Comparison shape (under ``expected``):
- ``finding_count: int`` — total OCSF 2003 findings (IaC + SAST).
- ``by_type: {discriminator: int}`` — per ``finding_info.types[0]``, checked when present.
- ``code_secret_count: int`` — rows in ``code_secrets.json`` (0 when absent), checked when present.

Registered via ``pyproject.toml`` ``[project.entry-points."nexus_eval_runners"]``
so ``eval-framework run --runner appsec`` resolves it.
"""

from __future__ import annotations

import json
from collections import Counter
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from appsec import agent as agent_mod
from appsec.normalizers.gitleaks_secrets import CODE_SECRETS_OUTPUT
from appsec.schemas import RepoRef
from appsec.tools.checkov_runner import CheckovResult
from appsec.tools.gitleaks_runner import GitleaksResult
from appsec.tools.scm_connector import StaticScmConnector
from appsec.tools.semgrep_runner import SemgrepResult

_DEFAULT_SLUG = "github/acme/api"


class AppSecEvalRunner:
    """Reference ``EvalRunner`` for the AppSec agent."""

    @property
    def agent_name(self) -> str:
        return "appsec"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        del llm_provider  # AppSec scanners are deterministic; no LLM in the loop
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        await _run_case_async(case, contract)

        ws = Path(contract.workspace)
        findings = _read_findings(ws)
        code_secret_count = _read_code_secret_count(ws)

        by_type = Counter(f["finding_info"]["types"][0] for f in findings)
        actuals: dict[str, Any] = {
            "finding_count": len(findings),
            "by_type": dict(by_type),
            "code_secret_count": code_secret_count,
        }
        passed, failure_reason = _evaluate(case, len(findings), by_type, code_secret_count)
        audit = ws / "audit.jsonl"
        return passed, failure_reason, actuals, audit if audit.exists() else None


# ---------------------------- internals ----------------------------------


async def _run_case_async(case: EvalCase, contract: ExecutionContract) -> None:
    """Patch the scanner wrappers per the fixture and run the agent."""
    fixture = case.fixture
    failed_checks = list(fixture.get("checkov_failed_checks", []))
    gitleaks_hits = list(fixture.get("gitleaks_hits", []))
    semgrep_results = list(fixture.get("semgrep_results", []))
    slug = str(fixture.get("repo_slug", _DEFAULT_SLUG))
    host, owner, name = [*slug.split("/", 2), "", "", ""][:3]

    async def fake_checkov(repo_path: str, **_: object) -> CheckovResult:
        del repo_path
        return CheckovResult(payload={"results": {"failed_checks": failed_checks}})

    async def fake_gitleaks(repo_path: str, **_: object) -> GitleaksResult:
        del repo_path
        return GitleaksResult(payload=gitleaks_hits)

    async def fake_semgrep(repo_path: str, **_: object) -> SemgrepResult:
        del repo_path
        return SemgrepResult(payload={"results": semgrep_results})

    repo = RepoRef(
        host=host or "github",
        owner=owner or "acme",
        name=name or "api",
        clone_url=f"https://example.test/{slug}.git",
        local_path=str(Path(contract.workspace).parent / "checkout"),
    )

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "run_checkov", fake_checkov))
        stack.enter_context(patch.object(agent_mod, "run_gitleaks", fake_gitleaks))
        stack.enter_context(patch.object(agent_mod, "run_semgrep", fake_semgrep))
        await agent_mod.run(contract=contract, scm_connector=StaticScmConnector([repo]))


def _read_findings(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "findings.json"
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = doc.get("findings", [])
    return findings


def _read_code_secret_count(workspace: Path) -> int:
    path = workspace / CODE_SECRETS_OUTPUT
    if not path.is_file():
        return 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    secrets: list[Any] = doc.get("secrets", [])
    return len(secrets)


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="appsec",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=200, mb_written=10
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
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(
    case: EvalCase,
    finding_count: int,
    by_type: Counter[str],
    code_secret_count: int,
) -> tuple[bool, str | None]:
    """Compare actuals to ``case.expected``. Returns (passed, failure_reason)."""
    expected_count = case.expected.get("finding_count")
    if expected_count is not None and finding_count != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {finding_count}"

    expected_by_type = case.expected.get("by_type") or {}
    for disc, want in expected_by_type.items():
        actual = by_type.get(str(disc), 0)
        if actual != int(want):
            return False, f"by_type '{disc}' expected {want}, got {actual}"

    expected_secrets = case.expected.get("code_secret_count")
    if expected_secrets is not None and code_secret_count != int(expected_secrets):
        return False, f"code_secret_count expected {expected_secrets}, got {code_secret_count}"

    return True, None


__all__ = ["AppSecEvalRunner"]
