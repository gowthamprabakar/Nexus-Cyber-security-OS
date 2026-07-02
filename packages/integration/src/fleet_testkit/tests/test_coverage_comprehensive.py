"""NEX-406 — the honest re-measure: a comprehensive fixture across all tactic groups.

The 29% baseline was a partial fixture. This plants families spanning every tactic group via the REAL
writers and measures the true climb, so the coverage % reflects the 28/28-built catalog rather than
one narrow scenario. Prints the measured number; asserts a floor well above the partial baseline.
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
from k8s_posture.rbac.enumerate import Role, RoleBinding, RoleRule, Subject
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from k8s_posture.tools.pod_reachability import PodRef, pod_reach_grants
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.coverage import measure_coverage
from network_threat.kg_writer import KnowledgeGraphWriter as NetKgWriter
from network_threat.tools.reachability import (
    IngressRule, NetworkInstance, SecurityGroup, VpcInstance, peering_reach_grants, reach_grants,
)
from vulnerability.kg_writer import KnowledgeGraphWriter as VulnKgWriter

from fleet_testkit import in_memory_semantic_store

_T = "cov-full"
_LK = "AKIA" + "EXAMPLEFULLLEAK1"
_SK = "AKIA" + "EXAMPLEFULLSTOR1"


async def _pub_data(store, arn, dt="ssn"):
    b = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id=arn, properties={"is_public": True})
    d = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                  external_id=f"{arn}:d", properties={"data_type": dt})
    await store.add_relationship(tenant_id=_T, src_entity_id=b, dst_entity_id=d,
                                 relationship_type=EdgeType.EXPOSES_DATA.value, properties={})
    return b, d


async def _vuln(store, res_arn, sev="CRITICAL"):
    r = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id=res_arn, properties={})
    c = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value, external_id=f"CVE-{res_arn[-4:]}", properties={"severity": sev})
    await store.add_relationship(tenant_id=_T, src_entity_id=r, dst_entity_id=c, relationship_type=EdgeType.VULNERABLE_TO.value, properties={})
    return r


@pytest.mark.asyncio
async def test_comprehensive_coverage_climb() -> None:
    async with in_memory_semantic_store() as store:
        ident, appsec, cloud, net, k8s, vuln = (
            IdentityKgWriter(store, _T), AppsecKgWriter(store, _T), CloudKgWriter(store, _T),
            NetKgWriter(store, _T), K8sKgWriter(store, _T), VulnKgWriter(store, _T))

        # credential access: leaked + stored + kms
        await appsec.record_leaked_credentials("o/a", [_LK]); await ident.record_credential_ownership([("u:ci", _LK)])
        await ident.record_access([("u:ci", "arn:aws:s3:::lk")]); await _pub_data(store, "arn:aws:s3:::lk")
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="svc:w", properties={"is_public": True})
        await cloud.record_stored_secrets(stored_secret_grants([("svc:w", [_SK])])); await ident.record_credential_ownership([("u:bot", _SK)])
        await ident.record_access([("u:bot", "arn:aws:s3:::st")]); await _pub_data(store, "arn:aws:s3:::st")
        await cloud.record_kms_protected_data([("arn:aws:kms:us-east-1:1:key/k", "ssn")]); await ident.record_access([("r:app", "arn:aws:kms:us-east-1:1:key/k")])

        # privilege escalation: iam privesc + cross-account + rbac
        await ident.record_escalation_grants([("u:dev", "r:admin", "self_grant_admin", "iam:x")])
        await ident.record_access([("r:admin", "arn:aws:s3:::pe")]); await _pub_data(store, "arn:aws:s3:::pe")
        role = IamRole(arn="arn:aws:iam::111111111111:role/p", name="p", role_id="A", create_date=None, last_used_at=None,  # type: ignore[arg-type]
                       assume_role_policy_document={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]})
        xa = cross_account_trust_grants([role]); await ident.record_external_trust([p for p, _ in xa]); await ident.record_assume_grants(xa)
        await ident.record_access([("arn:aws:iam::111111111111:role/p", "arn:aws:s3:::xa")]); await _pub_data(store, "arn:aws:s3:::xa")
        cl = "arn:aws:eks:us-east-1:1:cluster/p"
        await k8s.record_inventory(ClusterInventory(cluster_id=cl, namespaces=("prod",),
            service_accounts=(K8sServiceAccount(name="ci", namespace="prod", role_arn="r:eks"),),
            roles=(Role(name="admin", kind="ClusterRole", namespace="", rules=(RoleRule(api_groups=("*",), resources=("*",), verbs=("*",)),)),),
            role_bindings=(RoleBinding(name="b", kind="ClusterRoleBinding", namespace="", role_ref_kind="ClusterRole", role_ref_name="admin",
                                       subjects=(Subject(kind="ServiceAccount", name="ci", namespace="prod"),)),)))
        await k8s.record_privileged_workloads(cl, [PrivilegedWorkload("prod", "fh", "img:1", "ci")])
        await ident.record_access([("r:eks", "arn:aws:s3:::k8")]); await _pub_data(store, "arn:aws:s3:::k8")

        # lateral: network + pod + vpc peering
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:pub", properties={"is_public": True})
        await net.record_reachability(reach_grants((NetworkInstance("arn:pub", ("sg-w",)), NetworkInstance("arn:prv", ("sg-d",))),
                                                    (SecurityGroup("sg-d", (IngressRule("tcp", 5432, 5432, ("sg-w",)),)),)))
        await _vuln(store, "arn:prv")
        await k8s.record_pod_reachability(pod_reach_grants((PodRef(f"{cl}/namespace/prod/pod/fh", "prod"), PodRef(f"{cl}/namespace/prod/pod/vic", "prod"))))
        vp = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.K8S_OBJECT.value, external_id=f"{cl}/namespace/prod/pod/vic", properties={"kind": "pod"})
        vi = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="vi:1", properties={"kind": "container-image"})
        vc = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value, external_id="CVE-POD", properties={"severity": "HIGH"})
        await store.add_relationship(tenant_id=_T, src_entity_id=vp, dst_entity_id=vi, relationship_type=EdgeType.RUNS_IMAGE.value, properties={})
        await store.add_relationship(tenant_id=_T, src_entity_id=vi, dst_entity_id=vc, relationship_type=EdgeType.VULNERABLE_TO.value, properties={})
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:vpc-a", properties={"is_public": True})
        await net.record_peering_reachability(peering_reach_grants((VpcInstance("arn:vpc-a", "vpc-a"), VpcInstance("arn:vpc-b", "vpc-b")),
                                                                   frozenset({frozenset({"vpc-a", "vpc-b"})}))); await _vuln(store, "arn:vpc-b")

        # exposure/vuln: public workload + image vuln (internet_exposed_vulnerable), exposed DB, exposed KMS, SBOM
        pw = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:web", properties={"is_public": True})
        wi = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="web:1", properties={"kind": "container-image"})
        await store.add_relationship(tenant_id=_T, src_entity_id=pw, dst_entity_id=wi, relationship_type=EdgeType.RUNS_IMAGE.value, properties={})
        await vuln.record_sbom_packages("web:1", [("log4j", "CVE-2021-44228", "CRITICAL")])
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:db", properties={"kind": "rds-instance", "is_public": True})
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="arn:kms2", properties={"kind": "kms-key", "is_public": True})
        await _pub_data(store, "arn:aws:s3:::secretbucket", dt="private_key")  # public_secret (secret data-type)

        report = await measure_coverage(store, _T)
        print(f"\n=== COMPREHENSIVE COVERAGE ===\n{len(report.produced)}/{report.catalog_total} "
              f"= {report.coverage_pct:.0f}% of catalog ({report.built_coverage_pct:.0f}% of built)")
        print("produced:", sorted(report.produced))
        assert report.coverage_pct >= 50.0, "comprehensive fixture must measure well above the 29% partial baseline"
