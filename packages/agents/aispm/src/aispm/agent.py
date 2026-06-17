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

import os
from datetime import UTC, datetime

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from aispm import __version__ as agent_version
from aispm.posture.aws import evaluate_aws_ai
from aispm.posture.azure import evaluate_azure_ai
from aispm.posture.gcp import evaluate_gcp_ai
from aispm.posture.prompt_injection import evaluate_prompt_injection
from aispm.schemas import FindingsReport
from aispm.tools.aws_ai import AwsAiReader, read_aws_ai
from aispm.tools.azure_ai import AzureAiReader, read_azure_ai
from aispm.tools.garak import GarakRunner, run_garak
from aispm.tools.gcp_ai import GcpAiReader, read_gcp_ai

DEFAULT_NLAH_VERSION = "0.1.0"

#: Gate for active prompt-injection probing (Garak sends adversarial prompts → cost+safety).
_PROBE_GATE_ENV = "NEXUS_LIVE_AISPM_PROBE"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    AWS + Azure OpenAI + Vertex AI discovery wired (PR2-3). The Garak prompt-injection probe
    registers here in PR4 (each ``cloud_calls``-budgeted so the Charter tracks API usage).
    """
    reg = ToolRegistry()
    # One logical scan per cloud (several API calls) → representative cost.
    reg.register("discover_aws_ai", read_aws_ai, version="0.4.0", cloud_calls=10)
    reg.register("discover_azure_ai", read_azure_ai, version="0.4.0", cloud_calls=10)
    reg.register("discover_gcp_ai", read_gcp_ai, version="0.4.0", cloud_calls=10)
    # Active prompt-injection probe (gated). Higher cloud_calls — garak invokes the model
    # many times. Only invoked behind NEXUS_LIVE_AISPM_PROBE (or an injected test runner).
    reg.register("probe_garak", run_garak, version="0.4.0", cloud_calls=50)
    return reg


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
    aws_account_id: str | None = None,
    aws_region: str = "us-east-1",
    aws_profile: str | None = None,
    aws_reader: AwsAiReader | None = None,
    azure_subscription_id: str | None = None,
    azure_reader: AzureAiReader | None = None,
    gcp_project_id: str | None = None,
    gcp_location: str = "us-central1",
    gcp_reader: GcpAiReader | None = None,
    probe_target: str | None = None,
    probe_provider: str = "bedrock",
    probe_account_id: str | None = None,
    garak_runner: GarakRunner | None = None,
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the AI-SPM agent end-to-end under the runtime charter.

    Args:
        aws_account_id: When set, discover this AWS account's AI deployments (PR2 connector:
            SageMaker + Bedrock) and emit OCSF 2003 posture findings. None skips the connector.
        aws_region: AWS region for the discovery scan.
        aws_profile: Optional boto3 profile for the live discovery.
        aws_reader: Injectable AWS-AI reader seam (tests pass a deterministic fake). Default
            None → the live boto3-backed reader.
        semantic_store: opt-in fleet-graph sink (default None inert) consumed by the PR5
            ``kg_writer``; threaded now so the signature is stable.
    """
    del llm_provider  # reserved
    del semantic_store  # PR5 kg_writer consumes this; threaded for signature stability

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        report = FindingsReport(
            agent="aispm",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )

        # Connector: AWS AI discovery (PR2). Routed through the charter proxy (budget + audit;
        # call_tool audits only kwarg KEY names, so the reader object never enters the log).
        if aws_account_id is not None:
            aws_inventory = await ctx.call_tool(
                "discover_aws_ai",
                account_id=aws_account_id,
                region=aws_region,
                profile=aws_profile,
                reader=aws_reader,
            )
            for finding in evaluate_aws_ai(
                aws_inventory, envelope=envelope, detected_at=scan_started
            ):
                report.add_finding(finding)

        # Connector: Azure OpenAI discovery (PR3).
        if azure_subscription_id is not None:
            azure_inventory = await ctx.call_tool(
                "discover_azure_ai",
                subscription_id=azure_subscription_id,
                reader=azure_reader,
            )
            for finding in evaluate_azure_ai(
                azure_inventory, envelope=envelope, detected_at=scan_started
            ):
                report.add_finding(finding)

        # Connector: GCP Vertex AI discovery (PR3).
        if gcp_project_id is not None:
            gcp_inventory = await ctx.call_tool(
                "discover_gcp_ai",
                project_id=gcp_project_id,
                location=gcp_location,
                reader=gcp_reader,
            )
            for finding in evaluate_gcp_ai(
                gcp_inventory, envelope=envelope, detected_at=scan_started
            ):
                report.add_finding(finding)

        # (b) Prompt-injection (PR4): active Garak red-team. GATED — runs only when a target
        # is set AND NEXUS_LIVE_AISPM_PROBE=1 (or a test runner is injected). Default-off →
        # byte-identical. Emits OCSF 2004 detections. Garak is a subprocess (no torch in core).
        probe_enabled = garak_runner is not None or os.environ.get(_PROBE_GATE_ENV) == "1"
        if probe_target is not None and probe_enabled:
            garak_results = await ctx.call_tool(
                "probe_garak",
                target=probe_target,
                runner=garak_runner,
                output_dir=ctx.workspace_mgr.workspace / "garak_out",
            )
            for finding in evaluate_prompt_injection(
                garak_results,
                provider=probe_provider,
                account_id=probe_account_id or contract.customer_id,
                target=probe_target,
                envelope=envelope,
                detected_at=scan_started,
            ):
                report.add_finding(finding)

        report.scan_completed_at = datetime.now(UTC)
        ctx.write_output("findings.json", report.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("summary.md", _render_summary(report).encode("utf-8"))
        ctx.assert_complete()

    return report
