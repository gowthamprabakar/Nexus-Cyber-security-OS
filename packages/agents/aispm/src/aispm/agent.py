"""AI Security Posture Management (AI-SPM) agent driver — D.11 / Agent under ADR-007.

v0.4 Stage 2, PR1 (skeleton). Discovers the org's AI/ML deployments across cloud AI
services and (b) detects prompt-injection exposure. Emits **two** OCSF classes (ADR-020):
2003 for deployment-discovery posture, 2004 for prompt-injection detection.

Scope LOCKED (operator): (a) deployment discovery + (b) prompt-injection (Garak, gated).
Cloud discovery connectors (AWS Bedrock/SageMaker → Azure OpenAI → Vertex) land in PR2-3;
Garak red-team in PR4; the fleet-graph ``kg_writer`` (AI inventory on the coherent ADR-018
spine) in PR5.
"""

from __future__ import annotations

from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from aispm import __version__ as agent_version
from aispm.schemas import FindingsReport

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Empty in PR1 — the cloud AI-discovery readers (Bedrock/SageMaker/Azure-OpenAI/Vertex)
    register here in PR2-3, the Garak probe in PR4 (each ``cloud_calls``-budgeted).
    """
    return ToolRegistry()


def _envelope(contract: ExecutionContract, *, correlation_id: str, model_pin: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="aispm",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


def _render_summary(report: FindingsReport) -> str:
    counts = report.count_by_severity()
    lines = [
        "# AI Security Posture (AI-SPM)",
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
    """Run the AI-SPM agent end-to-end under the runtime charter.

    PR1 skeleton: no connectors wired yet → an empty (but valid) ``findings.json`` +
    ``summary.md``. ``semantic_store`` is the opt-in fleet-graph sink (default None inert)
    consumed by the PR5 ``kg_writer``; threaded now so the signature is stable.
    """
    del llm_provider  # reserved
    del semantic_store  # PR5 kg_writer consumes this; threaded for signature stability

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        _ = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Discovery + prompt-injection connectors (PR2-4) populate the report here.
        report = FindingsReport(
            agent="aispm",
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
