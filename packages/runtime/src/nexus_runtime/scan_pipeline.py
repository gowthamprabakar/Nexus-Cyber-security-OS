"""scan_run — run spine agents into one shared graph store, then call analyze.

This is the keystone of the operating-path wiring cycle.  Feeders write into a
single SemanticStore and are executed in dependency order (see binding constraint
in the task brief).  A bad feeder degrades coverage, never aborts: every feeder
call is wrapped in try/except and the partial graph is always passed to analyze.

Dependency order (load-bearing — mirrors correlation.py comment + plan):
  data-security → identity → cloud-posture (Task 9) → vulnerability →
  k8s-posture → network-threat → threat-intel → runtime-threat → aispm →
  appsec → analyze

This first cut builds only the data-security and identity feeders (TDD:
the Task 1 test exercises data-security; Task 3 exercises identity).  The
remaining feeders are wired by their own tasks listed below.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aispm.agent import run as aispm_run
from appsec.agent import run as appsec_run
from appsec.tools.scm_connector import ScmConnector
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from cloud_posture.agent import run as cloud_posture_run
from cloud_posture.tools.aws_ec2 import Ec2Workload
from cloud_posture.tools.aws_ecs import EcsWorkload
from cloud_posture.tools.aws_kms import KmsKey
from cloud_posture.tools.aws_rds import RdsInstance
from data_security.agent import run as data_security_run
from identity.agent import run as identity_run
from identity.tools.aws_iam import IdentityListing
from k8s_posture.agent import run as k8s_posture_run
from meta_harness.scan import analyze
from network_threat.agent import run as network_threat_run
from runtime_threat.agent import run as runtime_threat_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from threat_intel.agent import run as threat_intel_run
from ulid import ULID
from vulnerability.agent import run as vulnerability_run

# ---------------------------------------------------------------------------
# Permitted-tool lists — copied verbatim from correlation.py (single source of
# truth for the tool contracts used by these agents; grep source files listed
# below if updating).
# Source: packages/runtime/src/nexus_runtime/correlation.py
# Verified against: data-security/tests/test_agent.py,
#                   identity/tests/test_agent_unit.py
# ---------------------------------------------------------------------------

_DS_TOOLS: list[str] = [
    "read_s3_inventory",
    "read_s3_objects",
    "read_f3_findings",
]

_ID_TOOLS: list[str] = [
    "aws_iam_list_identities",
    "aws_iam_simulate_principal_policy",
    "aws_access_analyzer_findings",
    "detect_aws_saml_providers",
    "detect_aws_oidc_providers",
    "detect_azure_federated_domains",
    "detect_azure_oidc_providers",
]

_CP_TOOLS: list[str] = [
    "prowler_scan",
    "aws_s3_list_buckets",
    "aws_s3_describe",
    "aws_iam_list_users_without_mfa",
    "aws_iam_list_admin_policies",
    "kg_upsert_asset",
    "kg_upsert_finding",
]

_VULN_TOOLS: list[str] = [
    "trivy_image_scan",
    "trivy_fs_scan",
    "trivy_host_scan",
]

_K8S_TOOLS: list[str] = [
    "read_kube_bench",
    "read_polaris",
    "read_manifests",
]

_NET_TOOLS: list[str] = [
    "read_suricata_alerts",
    "read_vpc_flow_logs",
    "read_dns_logs",
]

_TI_TOOLS: list[str] = [
    "read_nvd_feed",
    "read_cisa_kev",
    "read_mitre_attack",
]

_RT_TOOLS: list[str] = [
    "falco_alerts_read",
    "tracee_alerts_read",
    "osquery_run",
]

_AISPM_TOOLS: list[str] = [
    "discover_aws_ai",
    "discover_azure_ai",
    "discover_gcp_ai",
    "probe_garak",
]

_APPSEC_TOOLS: list[str] = [
    "discover_repositories",
    "run_checkov",
    "run_gitleaks",
    "clone_repository",
    "run_semgrep",
]


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanSources:
    """All optional feed sources for the pipeline.

    Every field defaults to None.  A feeder is SKIPPED (no FeederOutcome
    emitted) when all of its required source fields are None.  Fields are
    kept for every eventual feeder even if the feeder is not yet wired, so
    callers constructed today won't break when later tasks add feeders.
    """

    # data-security feeds
    ds_inventory_feed: Path | None = None
    ds_objects_feed: Path | None = None

    # identity feed
    identity_listing: IdentityListing | None = None

    # vulnerability feeds
    vuln_image_refs: tuple[str, ...] | None = None

    # k8s-posture feeds
    k8s_kube_bench_feed: Path | None = None
    k8s_polaris_feed: Path | None = None
    k8s_manifest_dir: Path | None = None

    # network-threat feed
    network_vpc_flow_feed: Path | None = None

    # threat-intel snapshots
    threat_nvd_snapshot: Path | None = None
    threat_kev_snapshot: Path | None = None

    # runtime-threat feed
    runtime_falco_feed: Path | None = None

    # aispm injectable readers (object | None avoids importing heavy reader protocols here)
    aispm_aws_reader: object | None = None
    aispm_aws_account_id: str | None = None  # required to activate the AWS discovery path
    aispm_azure_reader: object | None = None
    aispm_gcp_reader: object | None = None

    # appsec connector
    appsec_scm_connector: ScmConnector | None = None

    # cloud-posture injectable workload params
    cloud_ec2_workloads: tuple[Ec2Workload, ...] | None = None
    cloud_ecs_workloads: tuple[EcsWorkload, ...] | None = None
    cloud_kms_keys: tuple[KmsKey, ...] | None = None
    cloud_rds_instances: tuple[RdsInstance, ...] | None = None

    # k8s-posture injectable cluster reader (ClusterReader protocol, or None).
    # When set, the offline k8s-posture path calls inventory_from_reader → record_inventory,
    # writing SA/RBAC nodes into the fleet graph (lights find_rbac_privilege_escalation).
    k8s_cluster_reader: object | None = None


@dataclass(frozen=True, slots=True)
class FeederOutcome:
    """Per-feeder execution record — ok=True iff the feeder completed without exception."""

    agent: str
    ok: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRunResult:
    """Combined pipeline result: confirmed + candidate attack paths + per-feeder records."""

    confirmed: list[object]  # list[meta_harness.attack_paths.AttackPath]
    candidates: list[object]  # list[meta_harness.path_engine.CandidatePath]
    feeders: list[FeederOutcome]  # one per EXECUTED feeder (skipped feeders absent)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _contract(
    tenant: str,
    target: str,
    tools: list[str],
    ws: Path,
    outputs: list[str],
) -> ExecutionContract:
    """Build an ExecutionContract for a feeder agent.

    Copied verbatim from correlation.py to keep the tool-contract shape identical.
    """
    ws.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=str(ULID()),
        source_agent="scan_run",
        target_agent=target,
        customer_id=tenant,
        task=f"scan_run: {target}",
        required_outputs=outputs,
        budget=BudgetSpec(
            llm_calls=5,
            tokens=20_000,
            wall_clock_sec=120.0,
            cloud_api_calls=500,
            mb_written=20,
        ),
        permitted_tools=tools,
        completion_condition="outputs exist",
        escalation_rules=[],
        workspace=str(ws),
        persistent_root=str(ws / "persistent"),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------


async def scan_run(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    sources: ScanSources,
    workspace_root: Path,
) -> ScanRunResult:
    """Run whichever spine agents have feeds present, then call analyze.

    Each feeder whose required source(s) are non-None is executed.  A feeder
    exception is caught and recorded as ok=False; analyze always runs on the
    partial graph so coverage degradation is surfaced, not a hard abort.

    Feeder dependency order is enforced by the ``await`` sequence below
    (data-security must write CLOUD_RESOURCE + EXPOSES_DATA before identity
    can write HAS_ACCESS_TO; all writes precede analyze).
    """
    store = SemanticStore(session_factory)
    feeders: list[FeederOutcome] = []

    async def _feed(name: str, needed: bool, coro_factory: object) -> None:
        """Run one feeder; skip if not needed; catch exceptions to degrade coverage."""
        if not needed:
            return
        # Build contract + launch only when needed (lazy — skipped feeders cost nothing).
        try:
            await coro_factory()  # type: ignore[operator]
            feeders.append(FeederOutcome(name, True))
        except Exception as exc:  # bad feeder degrades coverage, never aborts
            feeders.append(FeederOutcome(name, False, f"{type(exc).__name__}: {exc}"))

    # ------------------------------------------------------------------
    # Dependency order (load-bearing — MUST NOT be reordered):
    # data-security writes CLOUD_RESOURCE nodes before identity reads them.
    # ------------------------------------------------------------------

    # 1. data-security
    await _feed(
        "data-security",
        sources.ds_inventory_feed is not None,
        lambda: data_security_run(
            _contract(
                tenant,
                "data_security",
                _DS_TOOLS,
                workspace_root / "data_security",
                ["findings.json", "report.md"],
            ),
            s3_inventory_feed=sources.ds_inventory_feed,
            s3_objects_feed=sources.ds_objects_feed,
            semantic_store=store,
        ),
    )

    # 2. identity
    await _feed(
        "identity",
        sources.identity_listing is not None,
        lambda: identity_run(
            _contract(
                tenant,
                "identity",
                _ID_TOOLS,
                workspace_root / "identity",
                ["findings.json", "summary.md"],
            ),
            iam_listing=sources.identity_listing,
            semantic_store=store,
        ),
    )

    # 3. cloud-posture (after identity; uses injectable workload seam from Task 9 / G-1)
    await _feed(
        "cloud-posture",
        (
            sources.cloud_ec2_workloads is not None
            or sources.cloud_ecs_workloads is not None
            or sources.cloud_kms_keys is not None
            or sources.cloud_rds_instances is not None
        ),
        lambda: cloud_posture_run(
            _contract(
                tenant,
                "cloud_posture",
                _CP_TOOLS,
                workspace_root / "cloud_posture",
                ["findings.json", "summary.md"],
            ),
            ec2_workloads=sources.cloud_ec2_workloads,
            ecs_workloads=sources.cloud_ecs_workloads,
            kms_keys=sources.cloud_kms_keys,
            rds_instances=sources.cloud_rds_instances,
            semantic_store=store,
        ),
    )

    # 4. vulnerability (image_refs scan; enrich=False keeps it deterministic/offline)
    await _feed(
        "vulnerability",
        bool(sources.vuln_image_refs),
        lambda: vulnerability_run(
            _contract(
                tenant,
                "vulnerability",
                _VULN_TOOLS,
                workspace_root / "vulnerability",
                ["findings.json", "summary.md"],
            ),
            image_refs=list(sources.vuln_image_refs or ()),
            enrich=False,
            semantic_store=store,
        ),
    )

    # 5. k8s-posture (manifest_dir feed or injectable cluster_reader)
    await _feed(
        "k8s-posture",
        sources.k8s_manifest_dir is not None or sources.k8s_cluster_reader is not None,
        lambda: k8s_posture_run(
            _contract(
                tenant,
                "k8s_posture",
                _K8S_TOOLS,
                workspace_root / "k8s_posture",
                ["findings.json", "report.md"],
            ),
            manifest_dir=sources.k8s_manifest_dir,
            cluster_reader=sources.k8s_cluster_reader,
            semantic_store=store,
        ),
    )

    # 6. network-threat (vpc_flow_feed)
    await _feed(
        "network-threat",
        sources.network_vpc_flow_feed is not None,
        lambda: network_threat_run(
            _contract(
                tenant,
                "network_threat",
                _NET_TOOLS,
                workspace_root / "network_threat",
                ["findings.json", "summary.md"],
            ),
            vpc_flow_feed=sources.network_vpc_flow_feed,
            semantic_store=store,
        ),
    )

    # 7. threat-intel (nvd + kev snapshots)
    await _feed(
        "threat-intel",
        (sources.threat_nvd_snapshot is not None or sources.threat_kev_snapshot is not None),
        lambda: threat_intel_run(
            _contract(
                tenant,
                "threat_intel",
                _TI_TOOLS,
                workspace_root / "threat_intel",
                ["findings.json", "summary.md"],
            ),
            nvd_snapshot=sources.threat_nvd_snapshot,
            kev_snapshot=sources.threat_kev_snapshot,
            semantic_store=store,
        ),
    )

    # 8. runtime-threat (falco_feed)
    await _feed(
        "runtime-threat",
        sources.runtime_falco_feed is not None,
        lambda: runtime_threat_run(
            _contract(
                tenant,
                "runtime_threat",
                _RT_TOOLS,
                workspace_root / "runtime_threat",
                ["findings.json", "summary.md"],
            ),
            falco_feed=sources.runtime_falco_feed,
            semantic_store=store,
        ),
    )

    # 9. aispm (injectable AWS/Azure/GCP AI readers)
    await _feed(
        "aispm",
        (
            sources.aispm_aws_reader is not None
            or sources.aispm_azure_reader is not None
            or sources.aispm_gcp_reader is not None
        ),
        lambda: aispm_run(
            _contract(
                tenant,
                "aispm",
                _AISPM_TOOLS,
                workspace_root / "aispm",
                ["findings.json", "summary.md"],
            ),
            aws_account_id=sources.aispm_aws_account_id,
            aws_reader=sources.aispm_aws_reader,  # type: ignore[arg-type]
            azure_reader=sources.aispm_azure_reader,  # type: ignore[arg-type]
            gcp_reader=sources.aispm_gcp_reader,  # type: ignore[arg-type]
            semantic_store=store,
        ),
    )

    # 10. appsec (scm_connector)
    await _feed(
        "appsec",
        sources.appsec_scm_connector is not None,
        lambda: appsec_run(
            _contract(
                tenant,
                "appsec",
                _APPSEC_TOOLS,
                workspace_root / "appsec",
                ["repo_inventory.json", "findings.json", "summary.md"],
            ),
            scm_connector=sources.appsec_scm_connector,
            semantic_store=store,
        ),
    )

    # ------------------------------------------------------------------
    # analyze always runs on whatever the feeders wrote (partial is fine)
    # ------------------------------------------------------------------
    scan_result = await analyze(store, tenant)

    return ScanRunResult(
        confirmed=list(scan_result.confirmed),
        candidates=list(scan_result.candidates),
        feeders=feeders,
    )


__all__ = ["FeederOutcome", "ScanRunResult", "ScanSources", "scan_run"]
