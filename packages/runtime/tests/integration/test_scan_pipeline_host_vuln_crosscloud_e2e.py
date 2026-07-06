"""End-to-end: host-vuln cross-cloud — VM-id join lights find_internet_exposed_host_vulnerable.

Cycle 4 P3 proof (task-4-report).

The detector ``find_internet_exposed_host_vulnerable`` is cloud-agnostic: it enumerates
CLOUD_RESOURCE nodes where ``is_public=True`` and follows a direct ``VULNERABLE_TO`` edge.
Before Cycle 4 P3, multi-cloud-posture wrote ``kind=vm-instance``+``is_public=True`` nodes
(via ``record_vm_instances``) but no ``VULNERABLE_TO`` edge reached those nodes through
``scan_run`` — the vulnerability feeder only received a scalar ``vuln_host_target_arn``.

After P3 the seam is widened: ``ScanSources.vuln_host_targets: tuple[(target, arn), ...]``
drives one ``vulnerability_run`` per VM, each keyed on the VM's native resource id
(``mc_vm_instances[].instance_id``).  The join key is the id shared between:
  - ``mc_vm_instances`` (multi_cloud_posture writes CLOUD_RESOURCE{is_public=True})
  - ``vuln_host_targets[i].arn`` (relabels the host-scan's ``_artifact_name``) so that
    ``kg_writer.record_scan_results`` writes the VULNERABLE_TO edge on the SAME node.

Two tests:

  1. Single-VM Azure: one public Azure VM (``/subscriptions/…/virtualMachines/vm-frontend``)
     gets a CRITICAL CVE → ``internet_exposed_host_vulnerable`` fires.  Would fail without
     the join (the is_public node and the VULNERABLE_TO node would have different keys).

  2. Multi-VM (Azure + GCP): two VMs in one scan_run call, each getting their own CVE via
     the list seam.  Both ``internet_exposed_host_vulnerable`` hits must be present and keyed
     on their respective VM ids.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.memory.models import Base
from multi_cloud_posture.tools.kg_writer import VmInstanceRecord
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from vulnerability.tools import trivy as trivy_mod

# ---------------------------------------------------------------------------
# Azure VM / GCP VM resource ids — the JOIN KEY between mc_vm_instances and
# vuln_host_targets.  These are arbitrary strings; real ids would be Azure
# resource ids or GCP compute resource names.
# ---------------------------------------------------------------------------

_AZURE_VM_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-frontend"
)
_GCP_VM_ID = "projects/my-project/zones/us-central1-a/instances/gce-backend"

_TENANT_SINGLE = "t-p3-azure-single"
_TENANT_MULTI = "t-p3-multi-vm"


# ---------------------------------------------------------------------------
# Session fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Fake trivy_host_scan — returns one CRITICAL CVE; _artifact_name intentionally
# absent so agent.run() relabels it to host_target_arn (the behaviour under test).
# ---------------------------------------------------------------------------


def _patch_trivy_host_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub trivy_host_scan: one CRITICAL CVE per call, _artifact_name NOT set."""

    async def _fake_host_scan(target: str, **_kw: Any) -> trivy_mod.TrivyResult:
        return trivy_mod.TrivyResult(
            raw_findings=[
                {
                    "VulnerabilityID": "CVE-2024-55555",
                    "PkgName": "openssh-server",
                    "InstalledVersion": "8.9p1",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSH RCE (cross-cloud fixture)",
                    "_target": f"{target} (ubuntu 22.04)",
                    "_class": "os-pkgs",
                    # _artifact_name deliberately absent — agent.run() must set it
                    # to host_target_arn (the P3 attribution logic under test).
                }
            ]
        )

    monkeypatch.setattr(trivy_mod, "trivy_host_scan", _fake_host_scan)


# ---------------------------------------------------------------------------
# Test 1 — single Azure VM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_host_vuln_crosscloud_azure_vm_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P3 proof: a public Azure VM gets a host CVE → find_internet_exposed_host_vulnerable fires.

    Two feeders cooperate in the shared SemanticStore:
      1. multi-cloud-posture: mc_vm_instances = [VmInstanceRecord(instance_id=_AZURE_VM_ID, is_public=True)]
         → record_vm_instances writes CLOUD_RESOURCE{kind=vm-instance, is_public=True} keyed on _AZURE_VM_ID.
      2. vulnerability: vuln_host_targets = [("/mnt/rootfs", _AZURE_VM_ID)]
         → vulnerability_run calls trivy_host_scan, relabels _artifact_name = _AZURE_VM_ID,
         → record_scan_results writes CLOUD_RESOURCE keyed on _AZURE_VM_ID + VULNERABLE_TO edge.

    The two feeders write to the SAME node (join key = _AZURE_VM_ID).
    analyze → find_internet_exposed_host_vulnerable → confirmed path.

    This test would FAIL without P3: without vuln_host_targets the vulnerability feeder
    is skipped (vuln_host_target is None), so no VULNERABLE_TO edge reaches the Azure VM node.
    """
    _patch_trivy_host_scan(monkeypatch)

    sources = ScanSources(
        # Feeder 1: multi-cloud-posture writes the public Azure VM spine node.
        mc_vm_instances=(
            VmInstanceRecord(
                instance_id=_AZURE_VM_ID,
                is_public=True,
            ),
        ),
        # Feeder 2 (P3 seam): vulnerability_run for this one VM, keyed on _AZURE_VM_ID.
        vuln_host_targets=(("/mnt/rootfs", _AZURE_VM_ID),),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT_SINGLE,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All feeders must succeed.
    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = [f.agent for f in res.feeders]
    assert "multi-cloud-posture" in feeder_names, (
        f"multi-cloud-posture feeder missing from {feeder_names}"
    )
    assert "vulnerability" in feeder_names, f"vulnerability feeder missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "internet_exposed_host_vulnerable" in path_types, (
        f"internet_exposed_host_vulnerable path not confirmed; got path_types={path_types}. "
        f"Join-key check: mc_vm_instances instance_id={_AZURE_VM_ID!r} (is_public=True); "
        f"vuln_host_targets arn={_AZURE_VM_ID!r} must relabel _artifact_name so the "
        f"VULNERABLE_TO node keys on the SAME id as the mc_vm_instances is_public node."
    )


# ---------------------------------------------------------------------------
# Test 2 — two VMs (Azure + GCP) via vuln_host_targets list seam
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_host_vuln_crosscloud_multi_vm_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P3 multi-VM proof: two VMs each get their own host CVE via vuln_host_targets list seam.

    Two mc_vm_instances (Azure + GCP) each flagged is_public=True.
    vuln_host_targets has two entries — one per VM, each with its own trivy target and
    instance_id as arn.  scan_run loops: two separate vulnerability_run calls, each
    relabeling _artifact_name to its respective VM id.  Both VMs end up with
    CLOUD_RESOURCE{is_public=True} + VULNERABLE_TO on the SAME node → two
    internet_exposed_host_vulnerable hits with distinct host_ids.

    This test would FAIL if the loop captured the wrong variable (closure hazard) or
    if one VM's CVE accidentally landed on the other VM's node.
    """
    _patch_trivy_host_scan(monkeypatch)

    sources = ScanSources(
        # Feeder 1: both VMs flagged public.
        mc_vm_instances=(
            VmInstanceRecord(instance_id=_AZURE_VM_ID, is_public=True),
            VmInstanceRecord(instance_id=_GCP_VM_ID, is_public=True),
        ),
        # Feeder 2 (P3 multi-VM seam): one entry per VM.
        vuln_host_targets=(
            ("/mnt/rootfs-azure", _AZURE_VM_ID),
            ("/mnt/rootfs-gcp", _GCP_VM_ID),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT_MULTI,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All feeders must succeed (multi-cloud-posture + two vulnerability runs).
    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    # Both vulnerability runs must have executed.
    vuln_outcomes = [f for f in res.feeders if f.agent == "vulnerability"]
    assert len(vuln_outcomes) == 2, (
        f"expected 2 vulnerability feeder outcomes (one per VM); got {len(vuln_outcomes)}: {vuln_outcomes}"
    )

    # Both VMs must produce internet_exposed_host_vulnerable hits — two separate paths,
    # one per VM, because AttackPathRanker groups by (path_type, (hv.host_id,)) and each
    # VM is a distinct CLOUD_RESOURCE node (different internal entity_id).
    path_types = [p.path_type for p in res.confirmed]
    assert path_types.count("internet_exposed_host_vulnerable") >= 2, (
        f"expected at least 2 internet_exposed_host_vulnerable paths (one per VM); "
        f"got path_types={path_types}. "
        f"Check that each vulnerability_run keyed on its own VM id and that both VMs "
        f"had is_public=True from mc_vm_instances."
    )

    # Two distinct host entity ids in the confirmed paths — proves the CVE from each
    # vulnerability_run landed on a different CLOUD_RESOURCE node (correct join key per VM).
    # host_id in HostVulnerableWorkload is the internal entity_id (ULID), not the external id.
    host_entity_ids = {
        entity
        for p in res.confirmed
        if p.path_type == "internet_exposed_host_vulnerable"
        for entity in p.entities
    }
    assert len(host_entity_ids) >= 2, (
        f"expected at least 2 distinct host entity_ids across internet_exposed_host_vulnerable paths; "
        f"got {len(host_entity_ids)}: {host_entity_ids}. "
        f"If only 1: both VMs' CVEs may have landed on the same node (wrong join key or "
        f"closure hazard in the vuln_host_targets loop)."
    )
