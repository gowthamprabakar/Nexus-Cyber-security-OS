"""Deep smoke — the whole moat in one graph → the report card.

Plants EVERY attack-path family the arc has built (privesc, network lateral, K8s escape, K8s pod
lateral, leaked credential, stored secret, cross-account trust) into ONE tenant graph via the REAL
writers, then asserts the generic engine surfaces them all and the report card renders them ranked
with fixes. This is the "watched the whole moat work together" proof.
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
from k8s_posture.tools.pod_reachability import PodRef, pod_reach_grants
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.path_engine import find_candidate_paths
from meta_harness.report_card import build_report_card, render_tenant_report_card
from network_threat.kg_writer import KnowledgeGraphWriter as NetKgWriter
from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup, reach_grants

from fleet_testkit import in_memory_semantic_store

_T = "megacorp"
_LEAKED_KEY = "AKIA" + "EXAMPLESMOKE0001"  # AKIA + exactly 16 chars (matches the detector regex)
_STORED_KEY = "AKIA" + "EXAMPLESMOKE0002"


async def _expose(store, arn):
    b = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id=arn, properties={"is_public": True})
    d = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                  external_id=f"{arn}/pii", properties={"data_type": "ssn"})
    await store.add_relationship(tenant_id=_T, src_entity_id=b, dst_entity_id=d,
                                 relationship_type=EdgeType.EXPOSES_DATA.value, properties={})


async def _vuln_host(store, arn):
    h = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id=arn, properties={})
    cve = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value,
                                    external_id=f"CVE-{arn[-4:]}", properties={"severity": "CRITICAL"})
    await store.add_relationship(tenant_id=_T, src_entity_id=h, dst_entity_id=cve,
                                 relationship_type=EdgeType.VULNERABLE_TO.value, properties={})


@pytest.mark.asyncio
async def test_full_moat_report_card() -> None:
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        appsec = AppsecKgWriter(store, _T)
        cloud = CloudKgWriter(store, _T)
        net = NetKgWriter(store, _T)
        k8s = K8sKgWriter(store, _T)

        # 1) privilege escalation → data
        await ident.record_escalation_grants(
            [("arn:aws:iam::1:user/dev", "arn:aws:iam::1:role/admin", "self_grant_admin", "iam:CreatePolicyVersion")]
        )
        await ident.record_access([("arn:aws:iam::1:role/admin", "arn:aws:s3:::privesc")])
        await _expose(store, "arn:aws:s3:::privesc")

        # 2) network lateral (CAN_REACH) → vulnerable host
        insts = (NetworkInstance("arn:pub-ec2", ("sg-web",)), NetworkInstance("arn:priv-ec2", ("sg-db",)))
        sgs = (SecurityGroup("sg-db", (IngressRule("tcp", 5432, 5432, ("sg-web",)),)),)
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id="arn:pub-ec2", properties={"is_public": True})
        await net.record_reachability(reach_grants(insts, sgs))
        await _vuln_host(store, "arn:priv-ec2")

        # 3) leaked AWS credential → data
        await appsec.record_leaked_credentials("megacorp/app", [_LEAKED_KEY])
        await ident.record_credential_ownership([("arn:aws:iam::1:user/ci", _LEAKED_KEY)])
        await ident.record_access([("arn:aws:iam::1:user/ci", "arn:aws:s3:::leaked")])
        await _expose(store, "arn:aws:s3:::leaked")

        # 4) stored secret in a public workload → owner's data
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id="arn:svc/web", properties={"is_public": True})
        await cloud.record_stored_secrets(stored_secret_grants([("arn:svc/web", [_STORED_KEY])]))
        await ident.record_credential_ownership([("arn:aws:iam::1:user/bot", _STORED_KEY)])
        await ident.record_access([("arn:aws:iam::1:user/bot", "arn:aws:s3:::stored")])
        await _expose(store, "arn:aws:s3:::stored")

        # 5) cross-account trust → data
        role = IamRole(arn="arn:aws:iam::111111111111:role/partner", name="partner", role_id="AROA1",
                       create_date=None, last_used_at=None,  # type: ignore[arg-type]
                       assume_role_policy_document={"Statement": [
                           {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]})
        xacct = cross_account_trust_grants([role])
        await ident.record_external_trust([p for p, _ in xacct])
        await ident.record_assume_grants(xacct)
        await ident.record_access([("arn:aws:iam::111111111111:role/partner", "arn:aws:s3:::partner")])
        await _expose(store, "arn:aws:s3:::partner")

        # 6) K8s container escape → cloud + pod-to-pod lateral
        cl = "arn:aws:eks:us-east-1:1:cluster/prod"
        from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
        await k8s.record_inventory(ClusterInventory(cluster_id=cl, namespaces=("prod",),
            service_accounts=(K8sServiceAccount(name="ci", namespace="prod", role_arn="arn:aws:iam::1:role/eks"),)))
        await k8s.record_privileged_workloads(cl, [PrivilegedWorkload("prod", "foothold", "img:1", "ci")])
        await ident.record_access([("arn:aws:iam::1:role/eks", "arn:aws:s3:::k8s")])
        await _expose(store, "arn:aws:s3:::k8s")
        pods = (PodRef(f"{cl}/namespace/prod/pod/foothold", "prod"), PodRef(f"{cl}/namespace/prod/pod/victim", "prod"))
        await k8s.record_pod_reachability(pod_reach_grants(pods))
        victim = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.K8S_OBJECT.value,
            external_id=f"{cl}/namespace/prod/pod/victim", properties={"kind": "pod"})
        vimg = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="victim-img:1", properties={"kind": "container-image"})
        vcve = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-POD-1", properties={"severity": "HIGH"})
        await store.add_relationship(tenant_id=_T, src_entity_id=victim, dst_entity_id=vimg,
                                     relationship_type=EdgeType.RUNS_IMAGE.value, properties={})
        await store.add_relationship(tenant_id=_T, src_entity_id=vimg, dst_entity_id=vcve,
                                     relationship_type=EdgeType.VULNERABLE_TO.value, properties={})

        # --- assertions: every new edge produces a discoverable path ---
        cands = await find_candidate_paths(store, _T)
        sigs = {e for c in cands for e in c.path.edge_signature}
        for edge in ("CAN_ESCALATE_TO", "CAN_REACH", "OWNED_BY", "STORES_SECRET",
                     "USES_SERVICE_ACCOUNT", "IRSA_MAPPING", "POD_CAN_REACH", "ASSUMES"):
            assert edge in sigs, f"{edge} produced no attack path"

        # the report card ranks them all, each with a fix, worst-first, readable labels
        cards = await build_report_card(store, _T, top_n=25)
        assert len(cards) >= 6
        assert all(c.fix for c in cards)
        assert [c.rank for c in cards] == sorted(c.rank for c in cards)
        assert cards[0].severity >= cards[-1].severity
        rendered = await render_tenant_report_card(store, _T, top_n=25)
        print("\n" + rendered)
        assert "ulid" not in rendered.lower()  # C1: no raw ULIDs, readable ARNs only
