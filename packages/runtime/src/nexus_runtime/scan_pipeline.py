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

from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from data_security.agent import run as data_security_run
from identity.agent import run as identity_run
from identity.tools.aws_iam import IdentityListing
from meta_harness.scan import analyze
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

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

    # appsec connector
    appsec_scm_connector: object | None = None

    # cloud-posture injectable workload params
    # cloud-posture feeder lands in Task 9 (needs injectable workload seam)
    cloud_ec2_workloads: tuple[object, ...] | None = None
    cloud_ecs_workloads: tuple[object, ...] | None = None


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
            cloud_api_calls=50,
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

    # cloud-posture feeder lands in Task 9 (needs injectable workload seam)

    # additional feeders (vuln/k8s/network/threat/runtime/appsec/cloud) added by
    # their wiring tasks + Task 11 e2e

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
