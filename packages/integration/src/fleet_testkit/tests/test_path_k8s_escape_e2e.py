"""W2 e2e — container escape → cloud compromise emerges as a real attack path.

A privileged pod can escape to the node and use its service account's IRSA-mapped cloud IAM role.
This drives the REAL k8s-posture writers (inventory IRSA leg + privileged-pod USES_SERVICE_ACCOUNT
leg) plus identity's access edge, and proves the walk emerges:
``privileged pod --USES_SERVICE_ACCOUNT--> SA --IRSA_MAPPING--> cloud role --HAS_ACCESS_TO--> data``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-k8s"
_CLUSTER = "arn:aws:eks:us-east-1:111:cluster/prod"
_ROLE = "arn:aws:iam::111:role/eks-ci"
_BUCKET = "arn:aws:s3:::crown"


@pytest.mark.asyncio
async def test_container_escape_to_cloud_data_emerges() -> None:
    async with in_memory_semantic_store() as store:
        k8s = K8sKgWriter(store, _T)
        # Inventory: the SA 'ci' in 'prod' is IRSA-mapped to a cloud IAM role.
        await k8s.record_inventory(
            ClusterInventory(
                cluster_id=_CLUSTER,
                namespaces=("prod",),
                service_accounts=(K8sServiceAccount(name="ci", namespace="prod", role_arn=_ROLE),),
            )
        )
        # A privileged pod in 'prod' runs as that SA.
        await k8s.record_privileged_workloads(
            _CLUSTER,
            [
                PrivilegedWorkload(
                    namespace="prod", name="runner", image_ref="img:1", service_account="ci"
                )
            ],
        )
        # The IRSA role can read the crown bucket, which exposes data (the cloud side).
        await IdentityKgWriter(store, _T).record_access([(_ROLE, _BUCKET)])
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        cands = await find_candidate_paths(store, _T)
        escape = [c for c in cands if "USES_SERVICE_ACCOUNT" in c.path.edge_signature]
        assert escape, "a privileged pod's escape to its IRSA cloud role's data must surface"
        sig = escape[0].path.edge_signature
        assert sig == ("USES_SERVICE_ACCOUNT", "IRSA_MAPPING", "HAS_ACCESS_TO", "EXPOSES_DATA")
        assert escape[0].path.sink_marker == "sensitive_data"
