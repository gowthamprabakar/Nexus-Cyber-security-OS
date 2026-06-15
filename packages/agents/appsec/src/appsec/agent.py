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

from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from shared.fabric.correlation import correlation_scope, new_correlation_id

from appsec import __version__ as agent_version
from appsec.schemas import FindingsReport, RepoInventory
from appsec.tools.repo_discovery import discover_repositories
from appsec.tools.scm_connector import ScmConnector, StaticScmConnector

_DISCOVER_TOOL = "discover_repositories"


def build_registry() -> ToolRegistry:
    """Compose the AppSec tool universe.

    v0.1 registers only repository discovery. ``cloud_calls`` reflects the live
    SCM API budget the connectors will consume in B-1 PR2 (the static connector
    spends none).
    """
    reg = ToolRegistry()
    reg.register(_DISCOVER_TOOL, discover_repositories, version="0.1.0", cloud_calls=50)
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
            scan_completed_at=datetime.now(UTC),
        )

        ctx.write_output("repo_inventory.json", inventory.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("findings.json", report.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("summary.md", _render_summary(inventory, report).encode("utf-8"))

        ctx.assert_complete()

    return inventory
