"""Heavy pressure test for the 4 most recent detection slices — #21 KMS, #20 RBAC, #15 host-vuln,
#14 lateral movement — before they carry product weight.

Banks measure recall on cases we handle; this hammers the BOUNDARIES the way test_known_limitations
does: false-positive resistance (near-miss inputs stay dark), idempotency (re-running feeders +
correlation doesn't duplicate paths), multi-tenant isolation, write-order independence, and the
honest recall gaps (inputs we deliberately miss, pinned so the gap is visible). The trivy-dependent
legs (#15/#14) gate on the real binary; KMS/RBAC are hermetic.

Each detector goes through its REAL agent reader/writer — no hand-faked graph nodes.
"""

import json

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.correlation import correlate_all
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.k8s_workloads import cluster_admin_rbac_reader, drive_cluster_inventory
from fleet_testkit.moto_aws import (
    drive_ec2_workloads,
    drive_kms_keys,
    moto_full_clients,
    moto_kms_client,
    setup_ec2_instance,
    setup_kms_key,
)
from fleet_testkit.network_intel import drive_network_flows
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

_ACCOUNT = "123456789012"
_VULN_FIXTURE = "Django==2.0.0\n"


# ---------------------------------------------------------------------------------------------
# #21 — exposed KMS key
# ---------------------------------------------------------------------------------------------


def _create_key_with_statement(kms: object, statement: dict) -> None:
    """Create a moto KMS key with a root-admin statement + the caller's extra statement."""
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]  # type: ignore[attr-defined]
    policy = {
        "Version": "2012-10-17",
        "Id": "key-policy",
        "Statement": [
            {
                "Sid": "root",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            statement,
        ],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))  # type: ignore[attr-defined]


async def _kms_public_count(statement: dict) -> int:
    async with in_memory_semantic_store() as store:
        with moto_kms_client() as kms:
            _create_key_with_statement(kms, statement)
            keys = await drive_kms_keys(store, tenant_id="t", kms_client=kms)
        return sum(1 for k in keys if k.is_public)


@pytest.mark.asyncio
async def test_kms_org_scoped_wildcard_is_not_public() -> None:
    # FP resistance: a `Principal: *` scoped by aws:PrincipalOrgID is the common org-shared key —
    # NOT internet-open. (Was a false positive before the condition-scoping fix.)
    assert (
        await _kms_public_count(
            {
                "Sid": "org",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            }
        )
        == 0
    )


@pytest.mark.asyncio
async def test_kms_securetransport_only_wildcard_is_still_public() -> None:
    # No false negative: aws:SecureTransport does NOT narrow WHO can use the key — a wildcard with
    # only that condition is still internet-open and must stay lit.
    assert (
        await _kms_public_count(
            {
                "Sid": "tls",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        )
        == 1
    )


@pytest.mark.asyncio
async def test_kms_named_account_principal_is_not_public() -> None:
    # FP resistance: a grant to a specific account root is not a wildcard exposure.
    assert (
        await _kms_public_count(
            {
                "Sid": "acct",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        )
        == 0
    )


@pytest.mark.asyncio
async def test_kms_idempotent_and_scaled() -> None:
    # Scale + idempotency: many keys, only the public ones light up, and re-driving the reader
    # does not produce duplicate paths (upsert dedup).
    async with in_memory_semantic_store() as store:
        with moto_kms_client() as kms:
            for _ in range(8):
                setup_kms_key(kms, public=False)
            for _ in range(3):
                setup_kms_key(kms, public=True)
            await drive_kms_keys(store, tenant_id="t", kms_client=kms)
            await drive_kms_keys(store, tenant_id="t", kms_client=kms)  # second pass
        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        assert len([p for p in paths if p.path_type == "exposed_kms_key"]) == 3


# ---------------------------------------------------------------------------------------------
# #20 — K8s RBAC privilege escalation
# ---------------------------------------------------------------------------------------------


class _RbacReader:
    """Minimal canned ClusterReader for arbitrary roles/bindings (pressure scenarios)."""

    def __init__(self, *, sas, roles, bindings) -> None:
        self._sas, self._roles, self._bindings = sas, roles, bindings

    def list_namespaces(self):
        return [{"metadata": {"name": "default"}}]

    def list_service_accounts(self):
        return [{"metadata": {"name": n, "namespace": "default"}} for n in self._sas]

    def list_roles(self):
        return self._roles

    def list_role_bindings(self):
        return self._bindings


def _clusterrole(name: str, rules: list[dict]) -> dict:
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": rules}


def _binding(name: str, role: str, subject: dict) -> dict:
    return {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": {"kind": "ClusterRole", "name": role},
        "subjects": [subject],
    }


def _sa_subject(name: str) -> dict:
    return {"kind": "ServiceAccount", "name": name, "namespace": "default"}


async def _rbac_paths(reader) -> list:
    async with in_memory_semantic_store() as store:
        await drive_cluster_inventory(store, tenant_id="t", cluster_id="c", reader=reader)
        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        return [p for p in paths if p.path_type == "rbac_privilege_escalation"]


@pytest.mark.asyncio
async def test_rbac_scoped_role_is_not_privesc() -> None:
    # FP resistance: wildcard verbs on a SPECIFIC resource, and specific verbs on wildcard
    # resources, are each NOT cluster-admin — neither should flag.
    reader = _RbacReader(
        sas=["a", "b"],
        roles=[
            _clusterrole(
                "secrets-admin", [{"apiGroups": ["*"], "resources": ["secrets"], "verbs": ["*"]}]
            ),
            _clusterrole(
                "readall", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get", "list"]}]
            ),
        ],
        bindings=[
            _binding("b1", "secrets-admin", _sa_subject("a")),
            _binding("b2", "readall", _sa_subject("b")),
        ],
    )
    assert await _rbac_paths(reader) == []


@pytest.mark.asyncio
async def test_rbac_split_rules_are_not_privesc() -> None:
    # FP resistance: wildcard verbs and wildcard resources SPLIT across two rules do NOT compose to
    # cluster-admin (each rule is its own unit) — must not flag.
    reader = _RbacReader(
        sas=["a"],
        roles=[
            _clusterrole(
                "split",
                [
                    {"apiGroups": ["*"], "resources": ["pods"], "verbs": ["*"]},
                    {"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]},
                ],
            )
        ],
        bindings=[_binding("b1", "split", _sa_subject("a"))],
    )
    assert await _rbac_paths(reader) == []


@pytest.mark.asyncio
async def test_rbac_user_subject_bound_to_admin_is_missed() -> None:
    # HONEST RECALL GAP: the writer only edges ServiceAccount subjects, so a human User bound to
    # cluster-admin is NOT graphed. Pinned so the gap is visible (close it → this assertion flips).
    reader = _RbacReader(
        sas=[],
        roles=[
            _clusterrole(
                "cluster-admin", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
            )
        ],
        bindings=[
            _binding("b1", "cluster-admin", {"kind": "User", "name": "alice", "namespace": ""})
        ],
    )
    assert await _rbac_paths(reader) == [], "user-subject privesc is a known, documented gap"


@pytest.mark.asyncio
async def test_rbac_admin_idempotent() -> None:
    # Idempotency: re-recording the inventory does not duplicate the privesc path.
    async with in_memory_semantic_store() as store:
        reader = cluster_admin_rbac_reader(admin=True)
        await drive_cluster_inventory(store, tenant_id="t", cluster_id="c", reader=reader)
        await drive_cluster_inventory(store, tenant_id="t", cluster_id="c", reader=reader)
        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        assert len([p for p in paths if p.path_type == "rbac_privilege_escalation"]) == 1


# ---------------------------------------------------------------------------------------------
# #15 — internet-exposed host OS vuln  (trivy-gated)
# ---------------------------------------------------------------------------------------------


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_host_vuln_does_not_fire_on_exposed_container(tmp_path) -> None:
    # FP resistance: an exposed CONTAINER workload carries its CVE on the IMAGE node (via
    # RUNS_IMAGE), not on the is_public workload node — the host detector must NOT report it.
    from fleet_testkit.moto_aws import drive_cloud_workloads, moto_ecs_clients, setup_ecs_workload

    (tmp_path / "requirements.txt").write_text(_VULN_FIXTURE)
    async with in_memory_semantic_store() as store:
        with moto_ecs_clients() as (ecs, ec2):
            setup_ecs_workload(ecs, ec2, image_ref="reg/app:1", public=True)
            await drive_cloud_workloads(store, tenant_id="t", ecs_client=ecs, ec2_client=ec2)
        await drive_vulnerability(store, tenant_id="t", fixture_dir=tmp_path, image_ref="reg/app:1")
        host = await KgQuery(store, "t").find_internet_exposed_host_vulnerable()
        assert host == [], "container CVE is on the image node, not a host-vuln"


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_host_vuln_write_order_independent(tmp_path) -> None:
    # Robustness: the host scan (creates/decorates the node kind -> scan-target) and the EC2 write
    # (sets is_public) can land in EITHER order; is_public must survive and the path fires both ways.
    from cloud_posture.tools.aws_ec2 import read_ec2_workloads

    (tmp_path / "requirements.txt").write_text(_VULN_FIXTURE)
    for scan_first in (True, False):
        async with in_memory_semantic_store() as store:
            with moto_full_clients(()) as (_s, iam, _e, ec2, _m):
                setup_ec2_instance(ec2, name="h", public=True)
                arn = read_ec2_workloads(ec2, iam)[0].instance_arn  # ARN without writing yet
                if scan_first:
                    await drive_vulnerability(
                        store, tenant_id="t", fixture_dir=tmp_path, image_ref=arn
                    )
                    await drive_ec2_workloads(store, tenant_id="t", ec2_client=ec2, iam_client=iam)
                else:
                    await drive_ec2_workloads(store, tenant_id="t", ec2_client=ec2, iam_client=iam)
                    await drive_vulnerability(
                        store, tenant_id="t", fixture_dir=tmp_path, image_ref=arn
                    )
            hits = await KgQuery(store, "t").find_internet_exposed_host_vulnerable()
            assert hits, f"host-vuln must fire (scan_first={scan_first})"


# ---------------------------------------------------------------------------------------------
# #14 — network lateral movement  (trivy-gated)
# ---------------------------------------------------------------------------------------------


async def _lateral_scene(tmp_path, *, flow, foothold_public=True):
    """Build a foothold + a vulnerable internal target with a given (src,dst) flow; return paths.

    The target is always the 10.0.2.x instance (picked by subnet, so it works even when the
    foothold is also private). ``flow(fip, tip)`` returns the observed (src, dst) IP pair.
    """
    (tmp_path / "requirements.txt").write_text(_VULN_FIXTURE)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s, iam, _e, ec2, _m):
            fip = setup_ec2_instance(ec2, name="foothold", public=foothold_public)
            tip = setup_ec2_instance(ec2, name="target", public=False, subnet_cidr="10.0.2.0/24")
            workloads = await drive_ec2_workloads(
                store, tenant_id="t", ec2_client=ec2, iam_client=iam
            )
        target = next(w for w in workloads if any(ip.startswith("10.0.2") for ip in w.private_ips))
        src, dst = flow(fip, tip)
        await drive_network_flows(store, tenant_id="t", flows=((src, dst),))
        await drive_vulnerability(
            store, tenant_id="t", fixture_dir=tmp_path, image_ref=target.instance_arn
        )
        await correlate_all(store, "t")
        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        return [p for p in paths if p.path_type == "lateral_movement"]


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_lateral_reverse_direction_is_dark(tmp_path) -> None:
    # Directionality: a flow FROM the vulnerable target TO the public foothold is NOT lateral
    # movement (the public end must be the flow source). Must stay dark.
    lm = await _lateral_scene(tmp_path, flow=lambda fip, tip: (tip, fip))
    assert lm == [], "reverse-direction flow is not foothold->target lateral movement"


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_lateral_private_foothold_is_dark(tmp_path) -> None:
    # FP resistance: if the foothold is NOT internet-exposed, an internal->internal flow to a vuln
    # host is not a perimeter-breach lateral path.
    lm = await _lateral_scene(tmp_path, flow=lambda fip, tip: (fip, tip), foothold_public=False)
    assert lm == []


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_lateral_idempotent_under_repeated_correlation(tmp_path) -> None:
    # Idempotency: running correlate_all three times must not multiply the OWNED_BY bridge edges
    # into duplicate lateral paths (ADR-022 edge dedup).
    (tmp_path / "requirements.txt").write_text(_VULN_FIXTURE)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s, iam, _e, ec2, _m):
            fip = setup_ec2_instance(ec2, name="foothold", public=True)
            tip = setup_ec2_instance(ec2, name="target", public=False, subnet_cidr="10.0.2.0/24")
            workloads = await drive_ec2_workloads(
                store, tenant_id="t", ec2_client=ec2, iam_client=iam
            )
        target = next(w for w in workloads if not w.is_public)
        await drive_network_flows(store, tenant_id="t", flows=((fip, tip),))
        await drive_vulnerability(
            store, tenant_id="t", fixture_dir=tmp_path, image_ref=target.instance_arn
        )
        for _ in range(3):
            await correlate_all(store, "t")
        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        assert len([p for p in paths if p.path_type == "lateral_movement"]) == 1


# ---------------------------------------------------------------------------------------------
# Cross-cutting — multi-tenant isolation
# ---------------------------------------------------------------------------------------------


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_all_four_slices_coexist_and_rank(tmp_path) -> None:
    # Integration pressure: all 4 archetypes in ONE tenant graph. find_all must surface each path
    # type exactly once, with the right severities, ranked worst-first (no interference/dropout).
    (tmp_path / "requirements.txt").write_text(_VULN_FIXTURE)
    async with in_memory_semantic_store() as store:
        # KMS
        with moto_kms_client() as kms:
            setup_kms_key(kms, public=True)
            await drive_kms_keys(store, tenant_id="t", kms_client=kms)
        # RBAC
        await drive_cluster_inventory(
            store, tenant_id="t", cluster_id="c", reader=cluster_admin_rbac_reader(admin=True)
        )
        # Host-vuln + lateral (foothold -> vulnerable internal host)
        with moto_full_clients(()) as (_s, iam, _e, ec2, _m):
            fip = setup_ec2_instance(ec2, name="foothold", public=True)
            tip = setup_ec2_instance(ec2, name="target", public=False, subnet_cidr="10.0.2.0/24")
            workloads = await drive_ec2_workloads(
                store, tenant_id="t", ec2_client=ec2, iam_client=iam
            )
        foothold = next(w for w in workloads if w.is_public)
        target = next(w for w in workloads if not w.is_public)
        await drive_network_flows(store, tenant_id="t", flows=((fip, tip),))
        # The public foothold itself is also a host-vuln; the internal target carries the pivot CVE.
        await drive_vulnerability(
            store, tenant_id="t", fixture_dir=tmp_path, image_ref=foothold.instance_arn
        )
        await drive_vulnerability(
            store, tenant_id="t", fixture_dir=tmp_path, image_ref=target.instance_arn
        )
        await correlate_all(store, "t")

        paths = await AttackPathRanker(KgQuery(store, "t")).find_all()
        by_type = {p.path_type: p for p in paths}
        for expected in (
            "exposed_kms_key",
            "rbac_privilege_escalation",
            "internet_exposed_host_vulnerable",
            "lateral_movement",
        ):
            assert expected in by_type, f"{expected} missing from the combined graph"
        # Severities are stable and the list is sorted worst-first.
        sevs = [p.severity for p in paths]
        assert sevs == sorted(sevs, reverse=True), "paths must be ranked by descending severity"
        assert by_type["lateral_movement"].severity == 82
        assert by_type["rbac_privilege_escalation"].severity == 76


@pytest.mark.asyncio
async def test_multi_tenant_isolation_kms() -> None:
    # Tenant A's public key must NOT surface in tenant B's path list (tenant-scoped queries).
    async with in_memory_semantic_store() as store:
        with moto_kms_client() as kms:
            setup_kms_key(kms, public=True)
            await drive_kms_keys(store, tenant_id="tenant-a", kms_client=kms)
        a = await AttackPathRanker(KgQuery(store, "tenant-a")).find_all()
        b = await AttackPathRanker(KgQuery(store, "tenant-b")).find_all()
        assert [p for p in a if p.path_type == "exposed_kms_key"]
        assert b == [], "tenant-b sees none of tenant-a's paths"
