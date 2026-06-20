"""Fleet Test Level 1 — k8s-posture (D.6) wiring smoke.

Tier A: emits OCSF 2003 Compliance Findings (offline kube-bench feed) AND writes the fleet
graph (live cluster inventory) → the full §2.3 wiring assertions. Modeled on the two
reference harnesses (cloud-posture + runtime-threat).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). It does NOT measure precision/recall
or assert "the agent found the right violation" — that is L2 (v2 directive §3).

D.6 quirk (vs. cloud-posture): the agent emits findings from OFFLINE feeds
(kube-bench/Polaris/manifest), but only writes the fleet graph (cluster namespaces / service
accounts / RBAC + the IRSA bridge) when a LIVE cluster source (`kubeconfig` / `in_cluster`)
is configured AND a store is injected (agent.run §Stage 1.3). So Tier A drives BOTH a
`kube_bench_feed` (for the OCSF findings) and a `kubeconfig` (for the graph writes) — these
are compatible (only manifest_dir/kubeconfig/in_cluster count toward the one-workload-source
mutual exclusion; a kube-bench feed does not). The kg_writer writes K8S_OBJECT nodes always
and IDENTITY nodes when a ServiceAccount carries an IRSA role-ARN.

Cluster-context safety (Q3/WI-K8): `assert_single_cluster_context` is per-run, so the two
separate tenant runs never trip it. Each tenant is given a DISTINCT kubeconfig path so its
cluster_id (and therefore every cluster-scoped entity key) is distinct — making the
two-tenant disjointness check meaningful rather than vacuously colliding on a shared
cluster_id.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from charter.contract import ExecutionContract
from charter.memory.graph_types import NodeCategory
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)
from k8s_posture import agent as agent_mod
from k8s_posture.agent import run
from k8s_posture.rbac.enumerate import Role, RoleBinding, Subject
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from k8s_posture.tools.kube_bench import KubeBenchFinding

# kg tool names (read_cluster_inventory writes the graph) + the offline readers.
_PERMITTED = [
    "read_kube_bench",
    "read_polaris",
    "read_manifests",
    "read_cluster_workloads",
    "read_cluster_inventory",
]
# kg_writer.record_inventory writes K8S_OBJECT (always) + IDENTITY (IRSA-annotated SA).
_CATEGORIES = (NodeCategory.K8S_OBJECT, NodeCategory.IDENTITY)
_OCSF_CLASS = 2003  # Compliance Finding (k8s_posture re-exports F.3's wire shape)
_ROLE_ARN = "arn:aws:iam::111122223333:role/app-role"


def _kube_bench_finding() -> KubeBenchFinding:
    """A realistic FAIL kube-bench control → one OCSF 2003 finding (mirrors unit-test fakes)."""
    from datetime import UTC, datetime

    return KubeBenchFinding(
        control_id="1.1.1",
        control_text="Ensure API server pod spec file permissions",
        section_id="1.1",
        section_desc="Master Node Configuration Files",
        node_type="master",
        status="FAIL",
        severity_marker="",
        audit="stat -c %a /etc/k8s",
        actual_value="777",
        remediation="chmod 644",
        scored=True,
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
    )


def _inventory(cluster_id: str) -> ClusterInventory:
    """A single-cluster inventory: namespace + IRSA-annotated SA + plain SA + RBAC binding.

    The IRSA-annotated SA produces the IDENTITY node (IAM role ARN), so both kg categories
    are written (mirrors test_kg_writer.py's _inventory()).
    """
    return ClusterInventory(
        cluster_id=cluster_id,
        namespaces=("default",),
        service_accounts=(
            K8sServiceAccount(name="app-sa", namespace="default", role_arn=_ROLE_ARN),
            K8sServiceAccount(name="plain-sa", namespace="default"),
        ),
        roles=(Role(name="reader", kind="Role", namespace="default"),),
        role_bindings=(
            RoleBinding(
                name="rb",
                kind="RoleBinding",
                namespace="default",
                role_ref_kind="Role",
                role_ref_name="reader",
                subjects=(Subject(kind="ServiceAccount", name="app-sa", namespace="default"),),
            ),
        ),
    )


def _seed_tool_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the offline kube-bench reader (→ finding) and the live inventory reader (→ graph).

    `read_cluster_inventory` returns an inventory keyed by the per-run `cluster_id` the agent
    passes through (so distinct kubeconfig paths yield distinct, disjoint cluster subgraphs).
    `read_cluster_workloads` is stubbed empty — workload findings come from the kube-bench feed.
    """

    async def fake_kube_bench(*, path: Path, **_: Any) -> tuple[KubeBenchFinding, ...]:
        return (_kube_bench_finding(),)

    async def fake_inventory(*, cluster_id: str | None = None, **_: Any) -> ClusterInventory:
        return _inventory(cluster_id or "test-cluster")

    async def fake_workloads(**_: Any) -> tuple[()]:
        return ()

    monkeypatch.setattr(agent_mod, "read_kube_bench", fake_kube_bench)
    monkeypatch.setattr(agent_mod, "read_cluster_inventory", fake_inventory)
    monkeypatch.setattr(agent_mod, "read_cluster_workloads", fake_workloads)


def _contract(tmp_path: Path, **kwargs: Any) -> ExecutionContract:
    """`wiring_contract`, but with `required_outputs` set to this agent's actual outputs.

    D.6 quirk: the shared `wiring_contract` hardcodes `required_outputs=["findings.json",
    "summary.md"]`, but k8s-posture writes `findings.json` + `report.md` (NOT `summary.md`),
    so `ctx.assert_complete()` would fail. We keep the canonical L1 contract and override only
    the one differing field via pydantic `model_copy` rather than forking the shared builder.
    """
    base = wiring_contract(tmp_path, target_agent="k8s_posture", **kwargs)
    return base.model_copy(update={"required_outputs": ["findings.json", "report.md"]})


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_k8s_posture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · K8S_OBJECT + IDENTITY written ·
    audit chain hash-verifies · tenant isolation (distinct cluster_id per tenant)."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A — distinct kubeconfig path → distinct cluster context (Q3/WI-K8).
        ws_a = tmp_path / "a"
        kb_a = ws_a / "kb.json"
        kb_a.parent.mkdir(parents=True, exist_ok=True)
        kb_a.write_text("placeholder")
        kubeconfig_a = ws_a / "kubeconfig-a"
        kubeconfig_a.write_text("placeholder")
        contract_a = _contract(
            ws_a,
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            cloud_api_calls=10,
        )
        report_a = await run(
            contract_a,
            kube_bench_feed=kb_a,
            kubeconfig=kubeconfig_a,
            semantic_store=store,
        )

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.K8S_OBJECT)
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.IDENTITY)

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same shape under tenant_b on a DISTINCT cluster → disjoint subgraph
        ws_b = tmp_path / "b"
        kb_b = ws_b / "kb.json"
        kb_b.parent.mkdir(parents=True, exist_ok=True)
        kb_b.write_text("placeholder")
        kubeconfig_b = ws_b / "kubeconfig-b"
        kubeconfig_b.write_text("placeholder")
        contract_b = _contract(
            ws_b,
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            cloud_api_calls=10,
        )
        await run(
            contract_b,
            kube_bench_feed=kb_b,
            kubeconfig=kubeconfig_b,
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_k8s_posture_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store (and no live cluster) → no graph writes; findings still emit."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        kb = tmp_path / "kb.json"
        kb.write_text("placeholder")
        contract = _contract(
            tmp_path,
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            cloud_api_calls=10,
        )
        report = await run(contract, kube_bench_feed=kb, semantic_store=None)
        assert report.total >= 1  # detection still runs offline
        # The injected store (unused by the run) stays empty — inert/byte-identical offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
