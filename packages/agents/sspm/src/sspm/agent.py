"""SaaS Security Posture Management (SSPM) agent driver — D.10 / Agent under ADR-007.

v0.4 Stage 2, PR1 (skeleton). Discovers SaaS application posture across an org's SaaS
estate and emits OCSF v1.3 Compliance Findings (class_uid 2003, operator Q2). The
DEPTH-FIRST connector set (operator Q1: GitHub-org + M365 + Slack) lands in PR2-4; the
fleet-graph ``kg_writer`` (SaaS inventory on the coherent ADR-018 spine) in PR5.

ADR-007 pattern check: the agent ``run`` signature converges across agents —
``(contract, *, llm_provider, ..., semantic_store)``. SSPM follows the reference shape.
"""

from __future__ import annotations

from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from sspm import __version__ as agent_version
from sspm.schemas import FindingsReport

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Empty in PR1 — the GitHub-org / M365 / Slack connector tools register here in PR2-4
    (each ``cloud_calls``-budgeted so the Charter tracks SaaS API usage).
    """
    return ToolRegistry()


def _envelope(contract: ExecutionContract, *, correlation_id: str, model_pin: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="sspm",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


def _render_summary(report: FindingsReport) -> str:
    counts = report.count_by_severity()
    lines = [
        "# SaaS Security Posture (SSPM)",
        "",
        f"- Customer: {report.customer_id}",
        f"- Findings: {report.total}",
        f"- By severity: {counts}",
    ]
    return "\n".join(lines) + "\n"


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.4
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the SSPM agent end-to-end under the runtime charter.

    PR1 skeleton: no connectors are wired yet, so a run produces an empty (but valid)
    ``findings.json`` + ``summary.md``. ``semantic_store`` is the opt-in fleet-graph sink
    (default None inert) consumed by the PR5 ``kg_writer``; threaded now so the signature
    is stable.

    Returns:
        The :class:`FindingsReport`. Side effects: writes ``findings.json`` + ``summary.md``
        to the charter workspace and a hash-chained audit log.
    """
    del llm_provider  # reserved
    del semantic_store  # PR5 kg_writer consumes this; threaded for signature stability

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        _ = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Connectors (PR2-4) ingest + normalize into OCSF 2003 findings here.
        report = FindingsReport(
            agent="sspm",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )

        ctx.write_output("findings.json", report.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("summary.md", _render_summary(report).encode("utf-8"))
        ctx.assert_complete()

    return report
