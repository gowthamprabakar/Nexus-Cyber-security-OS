"""NEX-003 — measure the REAL attack-path coverage baseline (produced / catalog).

Plants the built families via the REAL writers, measures against the fixed 28-family catalog, and
prints the honest baseline %. Replaces the "~15–20%" estimate. Asserts a floor so regressions in the
engine (a family stops producing) are caught.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import EdgeType, NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudKgWriter
from cloud_posture.tools.stored_secrets import stored_secret_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.aws_iam import IamRole
from identity.tools.cross_account import cross_account_trust_grants
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from k8s_posture.tools.pod_reachability import PodRef, pod_reach_grants
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.coverage import measure_coverage
from meta_harness.coverage_catalog import CATALOG

from fleet_testkit import in_memory_semantic_store

_T = "cov"
_LK = "AKIA" + "EXAMPLECOVLEAK01"
_SK = "AKIA" + "EXAMPLECOVSTOR01"


async def _expose(store, arn):
    b = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id=arn, properties={"is_public": True})
    d = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                  external_id=f"{arn}/pii", properties={"data_type": "ssn"})
    await store.add_relationship(tenant_id=_T, src_entity_id=b, dst_entity_id=d,
                                 relationship_type=EdgeType.EXPOSES_DATA.value, properties={})


@pytest.mark.asyncio
async def test_coverage_baseline() -> None:
    from network_threat.kg_writer import KnowledgeGraphWriter as NetKgWriter
    from network_threat.tools.reachability import (
        IngressRule, NetworkInstance, SecurityGroup, reach_grants,
    )

    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        # privesc, leaked-cred, stored-secret, cross-account, network-lateral, k8s-escape, pod-lateral
        await ident.record_escalation_grants([("u:dev", "r:admin", "self_grant_admin", "iam:x")])
        await ident.record_access([("r:admin", "arn:aws:s3:::pe")]); await _expose(store, "arn:aws:s3:::pe")
        await AppsecKgWriter(store, _T).record_leaked_credentials("o/a", [_LK])
        await ident.record_credential_ownership([("u:ci", _LK)])
        await ident.record_access([("u:ci", "arn:aws:s3:::lk")]); await _expose(store, "arn:aws:s3:::lk")
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id="svc:web", properties={"is_public": True})
        await CloudKgWriter(store, _T).record_stored_secrets(stored_secret_grants([("svc:web", [_SK])]))
        await ident.record_credential_ownership([("u:bot", _SK)])
        await ident.record_access([("u:bot", "arn:aws:s3:::st")]); await _expose(store, "arn:aws:s3:::st")
        role = IamRole(arn="arn:aws:iam::111111111111:role/p", name="p", role_id="A", create_date=None,  # type: ignore[arg-type]
                       last_used_at=None, assume_role_policy_document={"Statement": [
                           {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]})
        xa = cross_account_trust_grants([role])
        await ident.record_external_trust([p for p, _ in xa]); await ident.record_assume_grants(xa)
        await ident.record_access([("arn:aws:iam::111111111111:role/p", "arn:aws:s3:::xa")]); await _expose(store, "arn:aws:s3:::xa")
        net = NetKgWriter(store, _T)
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id="arn:pub", properties={"is_public": True})
        await net.record_reachability(reach_grants(
            (NetworkInstance("arn:pub", ("sg-w",)), NetworkInstance("arn:prv", ("sg-d",))),
            (SecurityGroup("sg-d", (IngressRule("tcp", 5432, 5432, ("sg-w",)),)),)))
        pv = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:prv", properties={})
        cv = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value, external_id="CVE-1", properties={"severity": "CRITICAL"})
        await store.add_relationship(tenant_id=_T, src_entity_id=pv, dst_entity_id=cv, relationship_type=EdgeType.VULNERABLE_TO.value, properties={})
        k8s = K8sKgWriter(store, _T); cl = "arn:aws:eks:us-east-1:1:cluster/p"
        await k8s.record_inventory(ClusterInventory(cluster_id=cl, namespaces=("prod",),
            service_accounts=(K8sServiceAccount(name="ci", namespace="prod", role_arn="r:eks"),)))
        await k8s.record_privileged_workloads(cl, [PrivilegedWorkload("prod", "fh", "img:1", "ci")])
        await ident.record_access([("r:eks", "arn:aws:s3:::k8")]); await _expose(store, "arn:aws:s3:::k8")
        await k8s.record_pod_reachability(pod_reach_grants(
            (PodRef(f"{cl}/namespace/prod/pod/fh", "prod"), PodRef(f"{cl}/namespace/prod/pod/vic", "prod"))))
        vp = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.K8S_OBJECT.value, external_id=f"{cl}/namespace/prod/pod/vic", properties={"kind": "pod"})
        vi = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="vi:1", properties={"kind": "container-image"})
        vc = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value, external_id="CVE-2", properties={"severity": "HIGH"})
        await store.add_relationship(tenant_id=_T, src_entity_id=vp, dst_entity_id=vi, relationship_type=EdgeType.RUNS_IMAGE.value, properties={})
        await store.add_relationship(tenant_id=_T, src_entity_id=vi, dst_entity_id=vc, relationship_type=EdgeType.VULNERABLE_TO.value, properties={})

        report = await measure_coverage(store, _T)
        print(f"\n=== COVERAGE BASELINE ===\n{len(report.produced)}/{report.catalog_total} families "
              f"= {report.coverage_pct:.0f}% of catalog | {report.built_coverage_pct:.0f}% of BUILT")
        print("produced:", sorted(report.produced))
        print("catalog missing:", sorted({f.id for f in CATALOG} - report.produced))
        # Floor: this fixture must produce the moat families it plants (regression guard).
        assert {"privilege_escalation", "leaked_credential", "stored_secret", "cross_account_trust",
                "network_lateral", "container_escape_cloud", "pod_lateral"} <= report.produced
        assert report.coverage_pct >= 25.0  # measured baseline floor
