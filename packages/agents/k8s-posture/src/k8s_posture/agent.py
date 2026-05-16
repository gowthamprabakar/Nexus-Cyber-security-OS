"""Kubernetes Posture Agent driver — wires charter + 3 readers + 3 normalizers + dedup + summarizer.

Mirrors D.5's [`agent.py`](../../../multi-cloud-posture/src/multi_cloud_posture/agent.py)
shape (filesystem-only fan-out via TaskGroup) with the D.6-specific
**six-stage pipeline**. D.6 introduces a dedicated DEDUP stage between
NORMALIZE and SUMMARIZE — kube-bench / Polaris / manifest can flag the
same posture issue from different angles, and the composite-key
collapse gives operators one OCSF feed.

Six-stage pipeline (per the NLAH README):

1. INGEST     — three feeds concurrent via `asyncio.TaskGroup`
2. NORMALIZE  — kube-bench + Polaris + manifest → OCSF 2003 (F.3 re-export)
3. SCORE      — deterministic severity per source (in the normalizers + readers)
4. DEDUP      — `dedupe_overlapping` collapses on `(rule, namespace, workload_arn, 5min_bucket)`
5. SUMMARIZE  — render markdown report with per-namespace + CRITICAL pinned
6. HANDOFF    — write findings.json + report.md; emit audit chain

Differences from D.5:

- **Three** ingest tools (kube-bench / Polaris / manifest dir) — one fewer than D.5.
- **Three** normalizers — the third is `normalize_manifest`, all lifting per-source
  records into the F.3 OCSF 2003 wire shape via re-exported `build_finding`.
- **NEW: DEDUP stage** — `dedupe_overlapping` runs after the three normalizers'
  outputs are concatenated; same wire shape goes in and out.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from k8s_posture import __version__ as agent_version
from k8s_posture.dedup import dedupe_overlapping
from k8s_posture.normalizers.kube_bench import normalize_kube_bench
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.normalizers.polaris import normalize_polaris
from k8s_posture.schemas import FindingsReport
from k8s_posture.summarizer import render_summary
from k8s_posture.tools.cluster_workloads import read_cluster_workloads
from k8s_posture.tools.kube_bench import KubeBenchFinding, read_kube_bench
from k8s_posture.tools.manifests import ManifestFinding, read_manifests
from k8s_posture.tools.polaris import PolarisFinding, read_polaris

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register("read_kube_bench", read_kube_bench, version="0.1.0", cloud_calls=0)
    reg.register("read_polaris", read_polaris, version="0.1.0", cloud_calls=0)
    reg.register("read_manifests", read_manifests, version="0.1.0", cloud_calls=0)
    # v0.2 — live cluster reader. cloud_calls=1 marks it as making outbound API
    # calls so the Charter budget tracks it (kube-bench/polaris/manifests are all
    # filesystem reads).
    reg.register("read_cluster_workloads", read_cluster_workloads, version="0.2.0", cloud_calls=1)
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="k8s_posture",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    kube_bench_feed: Path | str | None = None,
    polaris_feed: Path | str | None = None,
    manifest_dir: Path | str | None = None,
    kubeconfig: Path | str | None = None,
    in_cluster: bool = False,
    cluster_namespace: str | None = None,
) -> FindingsReport:
    """Run the Kubernetes Posture Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        kube_bench_feed: Optional path to `kube-bench --json` output. Skipped if None.
        polaris_feed: Optional path to `polaris audit --format=json` output. Skipped if None.
        manifest_dir: Optional directory of `*.yaml` manifests (v0.1 source).
            **Mutually exclusive with `kubeconfig` and `in_cluster`** (Q6 / v0.3 Q2 —
            one workload source per run).
        kubeconfig: Optional path to a kubeconfig file (v0.2 source). Workload
            findings come from the live cluster via `read_cluster_workloads`
            instead of the file-based `read_manifests`.
        in_cluster: When True, load cluster config from the Pod's mounted
            ServiceAccount token (v0.3 source). Mutually exclusive with
            `manifest_dir` and `kubeconfig`.
        cluster_namespace: Optional namespace scope for live-cluster ingest (Q3).
            `None` → cluster-wide list APIs; a string → namespace-scoped APIs.
            Only honoured when `kubeconfig` or `in_cluster` is set.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `report.md` to the charter workspace; emits a hash-chained audit
        log at `audit.jsonl`.

    Raises:
        ValueError: when more than one workload source is supplied
            (mutually exclusive per Q6 / v0.3 Q2).
    """
    del llm_provider  # reserved for future iterations

    workload_sources = sum(1 for x in (manifest_dir, kubeconfig) if x is not None) + (
        1 if in_cluster else 0
    )
    if workload_sources > 1:
        raise ValueError(
            "manifest_dir, kubeconfig, and in_cluster are mutually exclusive — pick "
            "one workload source per run (Q6 / v0.3 Q2)"
        )

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1: INGEST — three feeds concurrent via TaskGroup.
        kb_records, polaris_records, manifest_records = await _ingest(
            ctx,
            kube_bench_feed=kube_bench_feed,
            polaris_feed=polaris_feed,
            manifest_dir=manifest_dir,
            kubeconfig=kubeconfig,
            in_cluster=in_cluster,
            cluster_namespace=cluster_namespace,
        )

        # Stage 2/3: NORMALIZE + SCORE.
        kb_findings = normalize_kube_bench(
            kb_records,
            envelope=envelope,
            scan_time=scan_started,
        )
        polaris_findings = normalize_polaris(
            polaris_records,
            envelope=envelope,
            scan_time=scan_started,
        )
        manifest_findings = normalize_manifest(
            manifest_records,
            envelope=envelope,
            scan_time=scan_started,
        )

        # Stage 4: DEDUP — composite-key collapse across all three sources.
        merged = (*kb_findings, *polaris_findings, *manifest_findings)
        deduped = dedupe_overlapping(merged)

        # Stage 5/6: SUMMARIZE + HANDOFF.
        report = FindingsReport(
            agent="k8s_posture",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in deduped:
            report.add_finding(f)

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "report.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


# ---------------------------- pipeline stages -----------------------------


async def _ingest(
    ctx: Charter,
    *,
    kube_bench_feed: Path | str | None,
    polaris_feed: Path | str | None,
    manifest_dir: Path | str | None,
    kubeconfig: Path | str | None,
    in_cluster: bool,
    cluster_namespace: str | None,
) -> tuple[
    Sequence[KubeBenchFinding],
    Sequence[PolarisFinding],
    Sequence[ManifestFinding],
]:
    """Stage 1 — fan out the three feeds via TaskGroup. Skipped feeds → empty tuple.

    Workload source routing (mutual exclusion enforced upstream in `run`):
    - `in_cluster=True` → live cluster via `read_cluster_workloads(in_cluster=True)` (v0.3).
    - `kubeconfig` set → live cluster via `read_cluster_workloads(kubeconfig=...)` (v0.2).
    - `manifest_dir` set → filesystem snapshots via `read_manifests` (v0.1).
    - None set → no workload findings.
    """
    async with asyncio.TaskGroup() as tg:
        kb_task = (
            tg.create_task(ctx.call_tool("read_kube_bench", path=Path(kube_bench_feed)))
            if kube_bench_feed
            else None
        )
        polaris_task = (
            tg.create_task(ctx.call_tool("read_polaris", path=Path(polaris_feed)))
            if polaris_feed
            else None
        )
        if in_cluster:
            workload_task = tg.create_task(
                ctx.call_tool(
                    "read_cluster_workloads",
                    in_cluster=True,
                    namespace=cluster_namespace,
                )
            )
        elif kubeconfig:
            workload_task = tg.create_task(
                ctx.call_tool(
                    "read_cluster_workloads",
                    kubeconfig=Path(kubeconfig),
                    namespace=cluster_namespace,
                )
            )
        elif manifest_dir:
            workload_task = tg.create_task(ctx.call_tool("read_manifests", path=Path(manifest_dir)))
        else:
            workload_task = None

    kb: Sequence[KubeBenchFinding] = kb_task.result() if kb_task else ()
    polaris: Sequence[PolarisFinding] = polaris_task.result() if polaris_task else ()
    manifest: Sequence[ManifestFinding] = workload_task.result() if workload_task else ()
    return kb, polaris, manifest


__all__ = ["build_registry", "run"]
