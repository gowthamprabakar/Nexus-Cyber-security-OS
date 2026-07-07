"""scan_run — run spine agents into one shared graph store, then call analyze.

This is the keystone of the operating-path wiring cycle.  Feeders write into a
single SemanticStore and are executed in dependency order (see binding constraint
in the task brief).  A bad feeder degrades coverage, never aborts: every feeder
call is wrapped in try/except and the partial graph is always passed to analyze.

Dependency order (load-bearing — mirrors correlation.py comment + plan):
  data-security → cloud-posture (Task 9, G-4) → identity → vulnerability →
  k8s-posture → network-threat → threat-intel → runtime-threat → aispm →
  appsec → analyze

  cloud-posture is promoted ahead of identity (G-4) so that kms-key / EC2 /
  ECS CLOUD_RESOURCE nodes exist when identity expands admin HAS_ACCESS_TO
  edges — the kms_key_access detector requires kms-key written before identity.

This first cut builds only the data-security and identity feeders (TDD:
the Task 1 test exercises data-security; Task 3 exercises identity).  The
remaining feeders are wired by their own tasks listed below.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aispm.agent import run as aispm_run
from appsec.agent import run as appsec_run
from appsec.tools.scm_connector import ScmConnector
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from cloud_posture.agent import run as cloud_posture_run
from cloud_posture.tools.aws_ec2 import Ec2Workload
from cloud_posture.tools.aws_ecs import EcsWorkload
from cloud_posture.tools.aws_kms import KmsKey
from cloud_posture.tools.aws_lambda import LambdaWorkload
from cloud_posture.tools.aws_logging import AccountLoggingState
from cloud_posture.tools.aws_rds import RdsInstance
from data_security.agent import run as data_security_run
from data_security.schemas import ClassifierLabel
from data_security.tools.azure_blob_inventory import AzureBlobContainer
from data_security.tools.gcs_inventory import GcsBucket
from identity.agent import run as identity_run
from identity.tools.aws_iam import IdentityListing
from identity.tools.azure_ad import AzureAdListing
from identity.tools.azure_rbac import AzureRoleAssignment
from identity.tools.gcp_iam import GcpIamBinding, GcpServiceAccountKey
from k8s_posture.agent import run as k8s_posture_run
from meta_harness.scan import analyze
from multi_cloud_posture.agent import run as multi_cloud_posture_run
from multi_cloud_posture.tools.kg_writer import KmsKeyRecord, SqlInstanceRecord, VmInstanceRecord
from network_threat.agent import run as network_threat_run
from network_threat.tools.reachability import NetworkInstance, SecurityGroup, VpcInstance
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

# Source: packages/agents/multi-cloud-posture/tests/test_kg_writer.py (_contract permitted_tools)
_MC_TOOLS: list[str] = [
    "read_azure_findings",
    "read_azure_activity",
    "read_gcp_findings",
    "read_gcp_iam_findings",
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
    # Cycle 4 P2 — Blob/GCS data-side (gap #13). When set, data_security.run() calls
    # record_data_sources so CLOUD_RESOURCE(azure_blob_uri / gcs_uri) --EXPOSES_DATA-->
    # DATA_CLASSIFICATION nodes land in the graph — the sink half of the native
    # fine-grained path.  None → S3-only behavior unchanged.
    ds_azure_blob_inventory: tuple[AzureBlobContainer, ...] | None = None
    ds_gcs_inventory: tuple[GcsBucket, ...] | None = None
    # Optional offline classifier hits for the Blob/GCS inventories above, keyed by
    # DataSource.identifier.  When set, record_data_sources writes
    # EXPOSES_DATA → DATA_CLASSIFICATION — required for find_fine_grained_data_exposure
    # to fire.  Live Blob/GCS object sampling (v0.5) will populate this automatically.
    ds_blob_gcs_classifier_hits: Mapping[str, tuple[ClassifierLabel, ...]] | None = None

    # identity feed
    identity_listing: IdentityListing | None = None
    # GCP-SA identity seam (Cycle 4 P1 — gap #13 parity). When set, identity.run() calls the GCP
    # IAM resolvers and writes the same graph edges as the AWS block (HAS_ACCESS_TO, CAN_ESCALATE_TO,
    # OWNS/OWNED_BY for SA keys, external_trust). None → AWS-only behavior unchanged.
    gcp_iam_bindings: tuple[GcpIamBinding, ...] | None = None
    gcp_sa_keys: tuple[GcpServiceAccountKey, ...] | None = None
    gcp_org_domain: str = ""
    # Azure-MI identity seam (Cycle 4 P1b — gap #13 parity). When set, identity.run() calls the
    # Azure resolvers and writes the same graph edges (HAS_ACCESS_TO, CAN_ESCALATE_TO, OWNS/OWNED_BY
    # for SP credential, external_trust for guest principals). None → unchanged behavior.
    azure_role_assignments: tuple[AzureRoleAssignment, ...] | None = None
    azure_ad_listing: AzureAdListing | None = None

    # vulnerability feeds
    vuln_image_refs: tuple[str, ...] | None = None
    # host-scan feed: vuln_host_target is the trivy target path/mode object;
    # vuln_host_target_arn (when set) keys the resulting VULNERABLE_TO node on the
    # instance ARN so it joins the cloud-posture is_public node (find_internet_exposed_host_vulnerable).
    vuln_host_target: object | None = None
    vuln_host_target_arn: str | None = None
    # Cycle 4 P3 — host-vuln cross-cloud multi-VM seam.  When set, the vulnerability
    # feeder runs once per (target, arn) pair so each VM's host CVE keys on its native
    # VM id (mc_vm_instances[].instance_id), making find_internet_exposed_host_vulnerable
    # fire cross-cloud.  Takes precedence over the scalar vuln_host_target /
    # vuln_host_target_arn when both are present.  None → scalar behavior unchanged.
    vuln_host_targets: tuple[tuple[object, str], ...] | None = None
    # injectable exploitability maps — passed through to vulnerability_run so the
    # kg_writer stamps kev=True / epss scores on VULNERABLE_TO edges.  When None,
    # unchanged behavior (enrich=False offline run gets no enrichment).
    vuln_kev_cve_ids: frozenset[str] | None = None
    vuln_epss_scores: Mapping[str, float] | None = None

    # k8s-posture feeds
    k8s_kube_bench_feed: Path | None = None
    k8s_polaris_feed: Path | None = None
    k8s_manifest_dir: Path | None = None

    # network-threat feed
    network_vpc_flow_feed: Path | None = None

    # network-threat topology seam (Cycle 2, Task 2)
    network_instances: Sequence[NetworkInstance] | None = None
    network_security_groups: Sequence[SecurityGroup] | None = None
    network_vpc_instances: Sequence[VpcInstance] | None = None
    network_vpc_peerings: frozenset[frozenset[str]] | None = None

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
    cloud_kms_protected_data: tuple[tuple[str, str], ...] | None = None
    cloud_lambda_workloads: tuple[LambdaWorkload, ...] | None = None
    cloud_rds_instances: tuple[RdsInstance, ...] | None = None
    # Cycle 8 T1 — defense-evasion ranking enrichment.  When set, the ranking model applies
    # _LOGGING_DISABLED_LIFT to every attack path in this account if logging_disabled is True
    # (CloudTrail not logging OR GuardDuty absent/disabled).  None → False → unchanged behavior.
    cloud_logging_state: AccountLoggingState | None = None

    # k8s-posture injectable cluster reader (ClusterReader protocol, or None).
    # When set, the offline k8s-posture path calls inventory_from_reader → record_inventory,
    # writing SA/RBAC nodes into the fleet graph (lights find_rbac_privilege_escalation).
    k8s_cluster_reader: object | None = None

    # multi-cloud-posture injectable resource seam (B-1/B-2).
    # When non-None, the multi-cloud-posture feeder writes Azure/GCP KMS/SQL/VM spine nodes
    # so the cloud-agnostic detectors (find_exposed_kms_key / find_exposed_database) fire
    # cross-cloud without any detector change. Mirrors cloud-posture's G-1 seam.
    mc_kms_keys: tuple[KmsKeyRecord, ...] | None = None
    mc_sql_instances: tuple[SqlInstanceRecord, ...] | None = None
    mc_vm_instances: tuple[VmInstanceRecord, ...] | None = None


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
    ocsf_findings: list[dict[str, Any]] = field(default_factory=list)  # OCSF 2005 Incident Findings


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
    (data-security + cloud-posture must write CLOUD_RESOURCE nodes before
    identity expands HAS_ACCESS_TO; all writes precede analyze).
    cloud-posture is ahead of identity so kms-key nodes exist when identity
    writes admin HAS_ACCESS_TO edges (G-4 / kms_key_access detector).
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
    # data-security + cloud-posture write CLOUD_RESOURCE nodes before
    # identity reads them.  cloud-posture is promoted ahead of identity so
    # that kms-key / EC2 / ECS nodes exist when identity expands admin
    # HAS_ACCESS_TO edges — the kms_key_access detector (G-4) requires this.
    # ------------------------------------------------------------------

    # 1. data-security
    await _feed(
        "data-security",
        sources.ds_inventory_feed is not None
        or sources.ds_azure_blob_inventory is not None
        or sources.ds_gcs_inventory is not None,
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
            azure_blob_inventory=sources.ds_azure_blob_inventory,
            gcs_inventory=sources.ds_gcs_inventory,
            blob_gcs_classifier_hits=sources.ds_blob_gcs_classifier_hits,
            semantic_store=store,
        ),
    )

    # 2. cloud-posture (before identity so kms-key / EC2 / ECS nodes exist when
    #    identity expands admin HAS_ACCESS_TO; uses injectable workload seam from Task 9 / G-1)
    await _feed(
        "cloud-posture",
        (
            sources.cloud_ec2_workloads is not None
            or sources.cloud_ecs_workloads is not None
            or sources.cloud_kms_keys is not None
            or sources.cloud_kms_protected_data is not None
            or sources.cloud_lambda_workloads is not None
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
            kms_protected_data=sources.cloud_kms_protected_data,
            lambda_workloads=sources.cloud_lambda_workloads,
            rds_instances=sources.cloud_rds_instances,
            semantic_store=store,
        ),
    )

    # 2b. multi-cloud-posture (after cloud-posture, before identity — Azure/GCP KMS/SQL/VM
    #     spine nodes must exist when identity expands HAS_ACCESS_TO edges cross-cloud).
    #     Enabled by any non-None mc_* source (B-1/B-2 injectable seam).
    await _feed(
        "multi-cloud-posture",
        (
            sources.mc_kms_keys is not None
            or sources.mc_sql_instances is not None
            or sources.mc_vm_instances is not None
        ),
        lambda: multi_cloud_posture_run(
            _contract(
                tenant,
                "multi_cloud_posture",
                _MC_TOOLS,
                workspace_root / "multi_cloud_posture",
                ["findings.json", "report.md"],
            ),
            mc_kms_keys=sources.mc_kms_keys,
            mc_sql_instances=sources.mc_sql_instances,
            mc_vm_instances=sources.mc_vm_instances,
            semantic_store=store,
        ),
    )

    # 3. identity (after data-security and cloud-posture so HAS_ACCESS_TO expansion
    #    covers all CLOUD_RESOURCE nodes — both bucket and kms-key nodes)
    await _feed(
        "identity",
        sources.identity_listing is not None
        or sources.gcp_iam_bindings is not None
        or sources.gcp_sa_keys is not None
        or sources.azure_role_assignments is not None
        or sources.azure_ad_listing is not None,
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
            gcp_iam_bindings=sources.gcp_iam_bindings,
            gcp_sa_keys=sources.gcp_sa_keys,
            gcp_org_domain=sources.gcp_org_domain,
            azure_role_assignments=sources.azure_role_assignments,
            azure_ad_listing=sources.azure_ad_listing,
        ),
    )

    # 4. vulnerability (image_refs scan or host scan; enrich=False keeps it deterministic/offline)
    #
    # Cycle 4 P3 — multi-VM host-vuln cross-cloud: when vuln_host_targets is set, run one
    # vulnerability_run per (target, arn) pair so each VM's host CVE lands on the correct
    # vm-instance node (join key = instance_id shared with mc_vm_instances).  Each run gets
    # its own workspace subdirectory (vulnerability/vm_{i}) to avoid output collisions.
    # The legacy scalar path (vuln_host_target / vuln_host_target_arn) is kept for backward
    # compatibility — it triggers when vuln_host_targets is None.
    if sources.vuln_host_targets is not None:
        for _idx, (_ht, _arn) in enumerate(sources.vuln_host_targets):
            _ht_cap, _arn_cap = _ht, _arn  # capture loop vars for the lambda
            await _feed(
                "vulnerability",
                True,
                lambda _h=_ht_cap, _a=_arn_cap, _i=_idx: vulnerability_run(
                    _contract(
                        tenant,
                        "vulnerability",
                        _VULN_TOOLS,
                        workspace_root / "vulnerability" / f"vm_{_i}",
                        ["findings.json", "summary.md"],
                    ),
                    host_target=_h,
                    host_target_arn=_a,
                    enrich=False,
                    kev_cve_ids=sources.vuln_kev_cve_ids,
                    epss_scores=sources.vuln_epss_scores,
                    semantic_store=store,
                ),
            )
    else:
        await _feed(
            "vulnerability",
            bool(sources.vuln_image_refs) or sources.vuln_host_target is not None,
            lambda: vulnerability_run(
                _contract(
                    tenant,
                    "vulnerability",
                    _VULN_TOOLS,
                    workspace_root / "vulnerability",
                    ["findings.json", "summary.md"],
                ),
                image_refs=list(sources.vuln_image_refs or ()),
                host_target=sources.vuln_host_target,  # type: ignore[arg-type]
                host_target_arn=sources.vuln_host_target_arn,
                enrich=False,
                kev_cve_ids=sources.vuln_kev_cve_ids,
                epss_scores=sources.vuln_epss_scores,
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

    # 6. network-threat (vpc_flow_feed or topology seam)
    await _feed(
        "network-threat",
        (
            sources.network_vpc_flow_feed is not None
            or sources.network_instances is not None
            or sources.network_vpc_instances is not None
        ),
        lambda: network_threat_run(
            _contract(
                tenant,
                "network_threat",
                _NET_TOOLS,
                workspace_root / "network_threat",
                ["findings.json", "report.md"],
            ),
            vpc_flow_feed=sources.network_vpc_flow_feed,
            network_instances=sources.network_instances,
            security_groups=sources.network_security_groups,
            vpc_instances=sources.network_vpc_instances,
            vpc_peerings=sources.network_vpc_peerings,
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
    scan_result = await analyze(
        store,
        tenant,
        persist=True,
        now=datetime.now(UTC),
        logging_disabled=(
            sources.cloud_logging_state is not None and sources.cloud_logging_state.logging_disabled
        ),
    )

    return ScanRunResult(
        confirmed=list(scan_result.confirmed),
        candidates=list(scan_result.candidates),
        feeders=feeders,
        ocsf_findings=scan_result.ocsf_findings,
    )


__all__ = ["FeederOutcome", "ScanRunResult", "ScanSources", "scan_run"]
