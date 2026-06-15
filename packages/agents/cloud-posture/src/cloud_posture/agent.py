"""Cloud Posture Agent driver — the template for Nexus production agents.

Wires the runtime charter, the four async tool wrappers, the OCSF schema
layer, the markdown summarizer, and the optional Postgres knowledge-graph
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
6. (Optional) Upsert assets + findings into the Postgres `SemanticStore`.
7. Charter exits — emits `invocation_completed`, clears contextvar, runs
   completion-condition assertion.

`llm_provider` is plumbed for future agents (Investigation, Synthesis); the
v0.1 Cloud Posture flow is deterministic — the LLM is not called. Per the
NLAH `Out-of-scope` section, customer-facing narration belongs to the
Synthesis Agent.

KG persistence rewired 2026-05-18 (KG-loop-closure plan) from a direct
Neo4j async driver to the platform's Postgres `SemanticStore`. The legacy
Neo4j writer at `cloud_posture/tools/neo4j_kg.py` is preserved DORMANT
against the future Phase-2 swap per ADR-009's escape hatch.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.degradation import degraded_marker
from charter.exceptions import BudgetExhausted
from charter.llm import LLMProvider
from charter.memory import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from cloud_posture import __version__ as agent_version
from cloud_posture.credentials import CredentialResolver
from cloud_posture.prowler_compliance import aggregate_cis_coverage, extract_cis_controls
from cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
)
from cloud_posture.summarizer import render_summary
from cloud_posture.tools import aws_account_discovery, aws_iam, aws_s3, prowler
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter

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


def build_registry(semantic_store: SemanticStore | None, customer_id: str) -> ToolRegistry:
    """Compose the tool universe available to this agent.

    KG tools (`kg_upsert_asset`, `kg_upsert_finding`) are registered only
    when `semantic_store` is provided. Without it the agent still produces
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

    if semantic_store is not None:
        kg = KnowledgeGraphWriter(semantic_store=semantic_store, customer_id=customer_id)
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


def _prowler_check_id(raw: dict[str, Any]) -> str:
    """Prowler check id — json-ocsf ``metadata.event_code``, legacy ``CheckID``.

    Dual-shape so the real Prowler json-ocsf output parses while the existing
    simplified-shape fixtures stay byte-identical. KeyError on a row carrying
    neither is caught by the caller (the row is dropped, not fatal).
    """
    meta = raw.get("metadata")
    if isinstance(meta, dict):
        event_code = meta.get("event_code")
        if isinstance(event_code, str) and event_code:
            return event_code
    return str(raw["CheckID"])


def _affected_from_prowler(raw: dict[str, Any]) -> AffectedResource:
    """Resource details — json-ocsf ``resources[0]`` + ``cloud``, legacy flat keys."""
    resources = raw.get("resources")
    if isinstance(resources, list) and resources:
        resource = resources[0]
        cloud_raw = raw.get("cloud")
        cloud: dict[str, Any] = cloud_raw if isinstance(cloud_raw, dict) else {}
        account_raw = cloud.get("account")
        account: dict[str, Any] = account_raw if isinstance(account_raw, dict) else {}
        arn = str(resource.get("uid", ""))
        account_id = str(account.get("uid", ""))
        region = str(cloud.get("region") or resource.get("region") or "")
        resource_type = str(resource.get("type", "")).lower()
    else:
        arn = raw["ResourceArn"]
        account_id = str(raw["AccountId"])
        region = str(raw["Region"])
        resource_type = str(raw["ResourceType"]).lower()
    resource_id = arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1] or arn
    return AffectedResource(
        cloud="aws",
        account_id=account_id,
        region=region,
        resource_type=resource_type,
        resource_id=resource_id,
        arn=arn,
    )


def _prowler_title(raw: dict[str, Any], check_id: str) -> str:
    """Title — json-ocsf ``finding_info.title``, legacy ``StatusExtended``."""
    finding_info = raw.get("finding_info")
    if isinstance(finding_info, dict):
        title = finding_info.get("title")
        if isinstance(title, str) and title:
            return title
    return str(raw.get("StatusExtended") or raw.get("status_detail") or check_id)


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
        check_id = _prowler_check_id(raw)
        rule_id = _rule_id_for(check_id)
        affected = _affected_from_prowler(raw)
        finding_id = f"{rule_id}-{_sanitize_context(affected.arn)}"
        severity = _PROWLER_SEVERITY_MAP.get(
            str(raw.get("severity", raw.get("Severity", "info"))).lower(), Severity.INFO
        )
        title = _prowler_title(raw, check_id)
        evidence: dict[str, Any] = {"prowler_check": check_id, "raw": raw}
        # A-3 (v0.3, option B): surface Prowler's NATIVE CIS attribution when the
        # json-ocsf output carries it (unmapped.compliance). Absent → no key →
        # findings from the simplified-shape fixtures stay byte-identical.
        cis_controls = extract_cis_controls(raw)
        if cis_controls:
            evidence["cis_controls"] = list(cis_controls)
        return build_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=title,
            affected=[affected],
            detected_at=datetime.now(UTC),
            envelope=_envelope(contract, model_pin=model_pin),
            evidence=evidence,
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
    semantic_store: SemanticStore | None = None,
    aws_account_id: str | None = None,
    aws_region: str = DEFAULT_AWS_REGION,
    aws_profile: str | None = None,
    discover_account: bool = False,
    regions: list[str] | None = None,
    discover_all_regions: bool = False,
) -> FindingsReport:
    """Run the Cloud Posture Agent end-to-end under the runtime charter.

    Returns the `FindingsReport`. Side effects: writes `findings.json` and
    `summary.md` to the charter workspace; emits a hash-chained audit log
    at `audit.jsonl`; optionally upserts assets + findings to the Postgres
    `SemanticStore` when `semantic_store` is provided.

    `llm_provider` is accepted to keep the call signature stable across
    later agents that DO drive their loops via LLM. Cloud Posture v0.1
    does not call it.
    """
    del llm_provider  # reserved for future iterations

    # Credentials + account resolution (v0.2 Tasks 2 + 3). `discover_account`
    # asks STS for the current account id (Q4: current-account only); an
    # explicit `aws_account_id` wins; otherwise fall back to the dev default so
    # the offline eval suite stays byte-identical.
    credential_resolver = CredentialResolver(profile=aws_profile)
    if discover_account:
        aws_account_id = await aws_account_discovery.discover_account_id(credential_resolver)
    elif aws_account_id is None:
        aws_account_id = DEFAULT_AWS_ACCOUNT_ID

    # Region scoping (v0.2 Task 4, Q3). An explicit `regions` list wins;
    # `discover_all_regions` → every available region (consumes Task 3); else
    # scope to the single `aws_region` (preserves the offline eval's
    # single-region, byte-identical behavior).
    if regions is not None:
        scan_regions = list(regions)
    elif discover_all_regions:
        scan_regions = await aws_account_discovery.discover_regions(credential_resolver)
    else:
        scan_regions = [aws_region]

    registry = build_registry(semantic_store, contract.customer_id)
    model_pin = "deterministic"  # no LLM calls in this flow
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        workspace = ctx.workspace_mgr.workspace

        # 1. Prowler scan — once per scoped region (Q3). Credentials resolved
        # above via the v0.2 seam (Q1-A / Q2). Findings are aggregated across
        # regions; the per-call return value is authoritative (output_dir is a
        # scratch path). v0.2 Task 5: a single region failing degrades that
        # region (recorded + surfaced in summary.md) instead of failing the
        # whole scan. A BudgetExhausted is a hard stop and is NOT degraded.
        prowler_raw: list[dict[str, Any]] = []
        degraded_regions: list[dict[str, str]] = []
        for region in scan_regions:
            try:
                region_result = await ctx.call_tool(
                    "prowler_scan",
                    account_id=aws_account_id,
                    region=region,
                    output_dir=workspace / "prowler_out",
                    profile=credential_resolver.profile,
                )
                prowler_raw.extend(region_result.raw_findings)
            except BudgetExhausted:
                raise  # budget is a hard stop, not a per-region degradation
            except Exception as exc:
                degraded_regions.append(degraded_marker("region", region, exc))

        # 2. IAM enrichment in parallel — IAM is a global service, so it is
        # called ONCE regardless of how many regions were scanned.
        async with asyncio.TaskGroup() as tg:
            users_task = tg.create_task(ctx.call_tool("aws_iam_list_users_without_mfa"))
            policies_task = tg.create_task(ctx.call_tool("aws_iam_list_admin_policies"))
        users_without_mfa: list[str] = users_task.result()
        admin_policies: list[dict[str, Any]] = policies_task.result()

        # 3. Build findings
        findings: list[CloudPostureFinding] = []
        for raw in prowler_raw:
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

        # 5. Knowledge-graph persistence (best-effort; only if SemanticStore provided)
        if semantic_store is not None:
            await _upsert_findings_to_kg(ctx, findings)

        # 6. Write outputs
        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "summary.md",
            render_summary(report, degraded_regions=degraded_regions).encode("utf-8"),
        )
        # A-3 (option B): roll up the native CIS controls Prowler emitted into a
        # coverage artifact (additive; findings.json byte-identical). Surfaces CSPM
        # CIS breadth using Prowler's own attributions — no hand-assigned mappings.
        cis_coverage = aggregate_cis_coverage([f.to_dict() for f in findings])
        ctx.write_output("cis_coverage.json", json.dumps(cis_coverage, indent=2).encode("utf-8"))

        ctx.assert_complete()
        return report


async def _upsert_findings_to_kg(ctx: Charter, findings: list[CloudPostureFinding]) -> None:
    """Upsert each finding's resources + the finding itself into SemanticStore."""
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
