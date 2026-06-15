"""AppSec Agent driver (D.14 v0.1) — charter + SCM repo discovery.

v0.1 (B-1 PR1) wires the substrate: open a charter, discover source repositories
via an injected ``ScmConnector`` (the charter-gated ``discover_repositories`` tool),
and write the three artifacts — ``repo_inventory.json`` (the discovery output),
``findings.json`` (empty until the B-1 PR2+ scanners), and ``summary.md``.

No OCSF emission yet (ADR-014: AppSec owns build-time; scanners land next). The
agent is deterministic: with the default empty ``StaticScmConnector`` it discovers
nothing and emits an empty inventory + report.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from shared.fabric.correlation import correlation_scope, new_correlation_id

from appsec import __version__ as agent_version
from appsec.normalizers.checkov_iac import checkov_to_findings
from appsec.normalizers.gitleaks_secrets import (
    CODE_SECRETS_OUTPUT,
    CodeSecretHit,
    gitleaks_to_secret_hits,
    render_code_secrets_json,
)
from appsec.ocsf.emission import finding_to_ocsf
from appsec.schemas import FindingsReport, RepoInventory
from appsec.tools.checkov_runner import run_checkov
from appsec.tools.gitleaks_runner import run_gitleaks
from appsec.tools.repo_discovery import discover_repositories
from appsec.tools.scm_connector import ScmConnector, StaticScmConnector

_DISCOVER_TOOL = "discover_repositories"
_CHECKOV_TOOL = "run_checkov"
_GITLEAKS_TOOL = "run_gitleaks"


def build_registry() -> ToolRegistry:
    """Compose the AppSec tool universe.

    v0.1 registers only repository discovery. ``cloud_calls`` reflects the live
    SCM API budget the connectors will consume in B-1 PR2 (the static connector
    spends none).
    """
    reg = ToolRegistry()
    reg.register(_DISCOVER_TOOL, discover_repositories, version="0.1.0", cloud_calls=50)
    # Checkov + gitleaks are local subprocesses (no cloud API), operator-provisioned.
    reg.register(_CHECKOV_TOOL, run_checkov, version="0.1.0", cloud_calls=0)
    reg.register(_GITLEAKS_TOOL, run_gitleaks, version="0.1.0", cloud_calls=0)
    return reg


def _render_summary(inventory: RepoInventory, report: FindingsReport) -> str:
    lines = [
        "# AppSec Scan Summary",
        "",
        f"- agent: {report.agent} (v{report.agent_version})",
        f"- customer: {report.customer_id}",
        f"- run: {report.run_id}",
        f"- repositories discovered: {inventory.total}",
        f"- findings: {report.total}",
        "",
    ]
    if inventory.repositories:
        lines.append("## Repositories")
        lines.extend(f"- {repo.slug} ({repo.visibility})" for repo in inventory.repositories)
    else:
        lines.append("_No repositories discovered (no live SCM connector configured)._")
    return "\n".join(lines) + "\n"


async def run(
    contract: ExecutionContract,
    *,
    scm_connector: ScmConnector | None = None,
) -> RepoInventory:
    """Run the AppSec agent: discover repositories and write artifacts.

    Args:
        contract: The signed ``ExecutionContract``.
        scm_connector: The SCM connector to discover repos through. Defaults to an
            empty ``StaticScmConnector`` (deterministic no-op discovery). B-1 PR2
            injects live GitHub/GitLab/Bitbucket connectors built from the
            Pattern-A ``ScmCredentialResolver``.

    Returns:
        The ``RepoInventory``. Side effects: writes ``repo_inventory.json``,
        ``findings.json``, ``summary.md`` to the charter workspace + the audit log.
    """
    connector = scm_connector if scm_connector is not None else StaticScmConnector()
    registry = build_registry()
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        repositories = await ctx.call_tool(_DISCOVER_TOOL, connector=connector)

        inventory = RepoInventory(
            agent="appsec",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            discovered_at=scan_started,
            repositories=tuple(repositories),
        )
        report = FindingsReport(
            agent="appsec",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=scan_started,
        )

        # Scan each repo checked out locally. Repos without a local_path are
        # skipped (live SCM checkout = a later B-1 PR).
        code_secret_hits: list[CodeSecretHit] = []
        for repo in inventory.repositories:
            if repo.local_path is None:
                continue
            # B-1 PR2 (Q-AppSec-3): Checkov IaC → OCSF 2003 findings.
            iac = await ctx.call_tool(_CHECKOV_TOOL, repo_path=repo.local_path)
            for finding in checkov_to_findings(iac.payload, repo_slug=repo.slug):
                report.add_finding(finding)
            # B-1 PR3 (Q-AppSec-4): gitleaks secrets-in-code → redacted DSPM
            # handoff (ADR-015: AppSec scans, DSPM emits OCSF 2003).
            leaks = await ctx.call_tool(_GITLEAKS_TOOL, repo_path=repo.local_path)
            code_secret_hits.extend(gitleaks_to_secret_hits(leaks))

        report.scan_completed_at = datetime.now(UTC)
        ocsf_findings = [
            finding_to_ocsf(
                f,
                customer_id=contract.customer_id,
                run_id=contract.delegation_id,
                detected_at=scan_started,
            )
            for f in report.findings
        ]
        findings_doc = {
            "agent": "appsec",
            "agent_version": agent_version,
            "customer_id": contract.customer_id,
            "run_id": contract.delegation_id,
            "scan_started_at": scan_started.isoformat(),
            "scan_completed_at": report.scan_completed_at.isoformat(),
            "findings": ocsf_findings,
        }

        ctx.write_output("repo_inventory.json", inventory.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("findings.json", json.dumps(findings_doc, indent=2).encode("utf-8"))
        ctx.write_output("summary.md", _render_summary(inventory, report).encode("utf-8"))
        # B-1 PR3 (ADR-015): hand off REDACTED secrets-in-code to DSPM (OCSF 2003
        # emit is DSPM's). Written only when secrets were found → byte-identical
        # otherwise. Plaintext never crosses (gitleaks Secret/Match dropped).
        if code_secret_hits:
            ctx.write_output(
                CODE_SECRETS_OUTPUT,
                render_code_secrets_json(run_id=contract.delegation_id, hits=code_secret_hits),
            )

        ctx.assert_complete()

    return inventory
