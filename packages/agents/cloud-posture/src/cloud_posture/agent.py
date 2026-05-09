"""Cloud Posture Agent driver — the template for Nexus production agents.

Wires the runtime charter, the four async tool wrappers, the OCSF schema
layer, the markdown summarizer, and the optional Neo4j knowledge-graph
writer into a single `async def run(contract, ...)` entry point.

Flow:
1. Open a `Charter(contract, tools=registry)` context (binds budget, audit,
   `current_charter()` contextvar; emits `invocation_started`).
2. Run Prowler against the contract's account/region.
3. Run IAM enrichment in parallel (`asyncio.TaskGroup`): users without MFA,
   admin-equivalent customer-managed policies.
4. Build OCSF Compliance Findings via `cloud_posture.schemas.build_finding`,
   each wrapped with a `NexusEnvelope` carrying correlation_id, tenant_id,
   agent_id, nlah_version, model_pin, charter_invocation_id.
5. Write `findings.json` (FindingsReport) and `summary.md` (rendered).
6. (Optional) Upsert assets + findings into the customer's Neo4j KG.
7. Charter exits — emits `invocation_completed`, clears contextvar, runs
   completion-condition assertion.

`llm_provider` is plumbed for future agents (Investigation, Synthesis); the
v0.1 Cloud Posture flow is deterministic — the LLM is not called. Per the
NLAH `Out-of-scope` section, customer-facing narration belongs to the
Synthesis Agent.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from cloud_posture import __version__ as agent_version
from cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
)
from cloud_posture.summarizer import render_summary
from cloud_posture.tools import aws_iam, aws_s3, prowler
from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter

NLAH_VERSION = "0.1.0"
DEFAULT_AWS_ACCOUNT_ID = "111122223333"
DEFAULT_AWS_REGION = "us-east-1"

# Severity mapping: Prowler emits lowercase string severities.
_PROWLER_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

# Stable rule_id assignment per Prowler CheckID. Unmapped CheckIDs fall
# back to a stable synthetic rule_id so finding_id format stays valid.
_PROWLER_RULE_MAP: dict[str, str] = {
    "iam_user_no_mfa": "CSPM-AWS-IAM-001",
    "s3_bucket_public_access": "CSPM-AWS-S3-001",
    "s3_bucket_no_encryption": "CSPM-AWS-S3-002",
    "kms_key_no_rotation": "CSPM-AWS-KMS-001",
    "rds_unencrypted": "CSPM-AWS-RDS-001",
    "open_security_group": "CSPM-AWS-EC2-001",
}

_RULE_IAM_NO_MFA = "CSPM-AWS-IAM-001"
_RULE_IAM_ADMIN_POLICY = "CSPM-AWS-IAM-002"

_CONTEXT_RE = re.compile(r"[^a-z0-9_-]")


# ----------------------------- registry --------------------------------------


def build_registry(neo4j_driver: Any | None, customer_id: str) -> ToolRegistry:
    """Compose the tool universe available to this agent.

    KG tools (`kg_upsert_asset`, `kg_upsert_finding`) are registered only
    when `neo4j_driver` is provided. Without it the agent still produces
    `findings.json` + `summary.md` and skips graph persistence.
    """
    reg = ToolRegistry()
    reg.register(
        "prowler_scan",
        prowler.run_prowler_aws,
        version="5.0.0",
        cloud_calls=200,
    )
    reg.register("aws_s3_list_buckets", aws_s3.list_buckets, version="1.35.0", cloud_calls=1)
    reg.register("aws_s3_describe", aws_s3.describe_bucket, version="1.35.0", cloud_calls=6)
    reg.register(
        "aws_iam_list_users_without_mfa",
        aws_iam.list_users_without_mfa,
        version="1.35.0",
        cloud_calls=10,
    )
    reg.register(
        "aws_iam_list_admin_policies",
        aws_iam.list_admin_policies,
        version="1.35.0",
        cloud_calls=10,
    )

    if neo4j_driver is not None:
        kg = KnowledgeGraphWriter(driver=neo4j_driver, customer_id=customer_id)
        reg.register("kg_upsert_asset", kg.upsert_asset, version="0.1.0", cloud_calls=0)
        reg.register("kg_upsert_finding", kg.upsert_finding, version="0.1.0", cloud_calls=0)
    return reg


# ----------------------------- helpers --------------------------------------


def _sanitize_context(s: str) -> str:
    """Map an arbitrary string into the FINDING_ID context grammar `[a-z0-9_-]+`."""
    s = s.lower().replace("/", "-").replace(":", "-")
    s = _CONTEXT_RE.sub("-", s)
    s = re.sub(r"-+", "-", s).strip("-_")
    return (s or "unknown")[:60]


def _rule_id_for(check_id: str) -> str:
    if check_id in _PROWLER_RULE_MAP:
        return _PROWLER_RULE_MAP[check_id]
    digest = hashlib.sha256(check_id.encode("utf-8")).hexdigest()
    nnn = int(digest[:6], 16) % 1000
    return f"CSPM-AWS-PROWLER-{nnn:03d}"


def _affected_from_prowler(raw: dict[str, Any]) -> AffectedResource:
    arn = raw["ResourceArn"]
    resource_id = arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1] or arn
    return AffectedResource(
        cloud="aws",
        account_id=str(raw["AccountId"]),
        region=str(raw["Region"]),
        resource_type=str(raw["ResourceType"]).lower(),
        resource_id=resource_id,
        arn=arn,
    )


def _envelope(contract: ExecutionContract, *, model_pin: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=new_correlation_id(),
        tenant_id=contract.customer_id,
        agent_id="cloud_posture",
        nlah_version=NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


def _finding_from_prowler(
    raw: dict[str, Any], *, contract: ExecutionContract, model_pin: str
) -> CloudPostureFinding | None:
    """Translate one Prowler raw OCSF emission into a Nexus OCSF finding.

    Returns `None` for malformed Prowler rows so a single bad row doesn't
    poison the whole report.
    """
    try:
        check_id = str(raw["CheckID"])
        rule_id = _rule_id_for(check_id)
        affected = _affected_from_prowler(raw)
        finding_id = f"{rule_id}-{_sanitize_context(affected.arn)}"
        severity = _PROWLER_SEVERITY_MAP.get(
            str(raw.get("Severity", "info")).lower(), Severity.INFO
        )
        title = str(raw.get("StatusExtended") or check_id)
        return build_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=title,
            affected=[affected],
            detected_at=datetime.now(UTC),
            envelope=_envelope(contract, model_pin=model_pin),
            evidence={"prowler_check": check_id, "raw": raw},
        )
    except (KeyError, ValueError):
        return None


def _iam_no_mfa_finding(
    username: str,
    *,
    contract: ExecutionContract,
    aws_account_id: str,
    aws_region: str,
    model_pin: str,
) -> CloudPostureFinding:
    arn = f"arn:aws:iam::{aws_account_id}:user/{username}"
    return build_finding(
        finding_id=f"{_RULE_IAM_NO_MFA}-{_sanitize_context(username)}",
        rule_id=_RULE_IAM_NO_MFA,
        severity=Severity.HIGH,
        title=f"IAM user '{username}' has console password but no MFA",
        description=(
            "Console-enabled users without MFA are a known credential-theft "
            "vector. Enable MFA or remove the login profile."
        ),
        affected=[
            AffectedResource(
                cloud="aws",
                account_id=aws_account_id,
                region=aws_region,
                resource_type="aws_iam_user",
                resource_id=username,
                arn=arn,
            )
        ],
        detected_at=datetime.now(UTC),
        envelope=_envelope(contract, model_pin=model_pin),
        evidence={"check": "list_mfa_devices returned []"},
    )


def _admin_policy_finding(
    policy: dict[str, Any],
    *,
    contract: ExecutionContract,
    aws_account_id: str,
    aws_region: str,
    model_pin: str,
) -> CloudPostureFinding:
    name = str(policy["policy_name"])
    arn = str(policy["policy_arn"])
    return build_finding(
        finding_id=f"{_RULE_IAM_ADMIN_POLICY}-{_sanitize_context(name)}",
        rule_id=_RULE_IAM_ADMIN_POLICY,
        severity=Severity.CRITICAL,
        title=f"Customer-managed policy '{name}' grants Action=* Resource=*",
        description=(
            "Any principal attached to this policy has admin equivalence. "
            "Detach or scope the statement immediately."
        ),
        affected=[
            AffectedResource(
                cloud="aws",
                account_id=aws_account_id,
                region=aws_region,
                resource_type="aws_iam_policy",
                resource_id=name,
                arn=arn,
            )
        ],
        detected_at=datetime.now(UTC),
        envelope=_envelope(contract, model_pin=model_pin),
        evidence={"document": policy.get("document", {})},
    )


# ----------------------------- run() ----------------------------------------


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    neo4j_driver: Any | None = None,
    aws_account_id: str = DEFAULT_AWS_ACCOUNT_ID,
    aws_region: str = DEFAULT_AWS_REGION,
) -> FindingsReport:
    """Run the Cloud Posture Agent end-to-end under the runtime charter.

    Returns the `FindingsReport`. Side effects: writes `findings.json` and
    `summary.md` to the charter workspace; emits a hash-chained audit log
    at `audit.jsonl`; optionally upserts assets + findings to Neo4j when
    `neo4j_driver` is provided.

    `llm_provider` is accepted to keep the call signature stable across
    later agents that DO drive their loops via LLM. Cloud Posture v0.1
    does not call it.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry(neo4j_driver, contract.customer_id)
    model_pin = "deterministic"  # no LLM calls in this flow
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        workspace = ctx.workspace_mgr.workspace

        # 1. Prowler scan
        prowler_result = await ctx.call_tool(
            "prowler_scan",
            account_id=aws_account_id,
            region=aws_region,
            output_dir=workspace / "prowler_out",
        )

        # 2. IAM enrichment in parallel — both calls are independent and read-only.
        async with asyncio.TaskGroup() as tg:
            users_task = tg.create_task(ctx.call_tool("aws_iam_list_users_without_mfa"))
            policies_task = tg.create_task(ctx.call_tool("aws_iam_list_admin_policies"))
        users_without_mfa: list[str] = users_task.result()
        admin_policies: list[dict[str, Any]] = policies_task.result()

        # 3. Build findings
        findings: list[CloudPostureFinding] = []
        for raw in prowler_result.raw_findings:
            f = _finding_from_prowler(raw, contract=contract, model_pin=model_pin)
            if f is not None:
                findings.append(f)

        for username in users_without_mfa:
            findings.append(
                _iam_no_mfa_finding(
                    username,
                    contract=contract,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    model_pin=model_pin,
                )
            )

        for policy in admin_policies:
            findings.append(
                _admin_policy_finding(
                    policy,
                    contract=contract,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    model_pin=model_pin,
                )
            )

        # 4. Build report
        report = FindingsReport(
            agent="cloud_posture",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in findings:
            report.add_finding(f)

        # 5. Knowledge-graph persistence (best-effort; only if driver provided)
        if neo4j_driver is not None:
            await _upsert_findings_to_kg(ctx, findings)

        # 6. Write outputs
        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "summary.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()
        return report


async def _upsert_findings_to_kg(ctx: Charter, findings: list[CloudPostureFinding]) -> None:
    """Upsert each finding's resources + the finding itself into Neo4j."""
    for finding in findings:
        for ocsf_resource in finding.resources:
            await ctx.call_tool(
                "kg_upsert_asset",
                kind=str(ocsf_resource.get("type", "unknown")),
                external_id=str(ocsf_resource.get("uid", "")),
                properties={
                    "region": ocsf_resource.get("region"),
                    "account_uid": (ocsf_resource.get("owner", {}).get("account_uid")),
                },
            )
        await ctx.call_tool(
            "kg_upsert_finding",
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            severity=finding.severity.value,
            affected_arns=[str(r.get("uid", "")) for r in finding.resources if r.get("uid")],
        )
