"""W4 e2e — K8s pod-to-pod lateral movement emerges as an attack path.

A privileged pod in a flat namespace can reach a neighbour pod that runs a vulnerable image. Drives
the REAL k8s writers (privileged workload + pod-reachability) and proves the walk:
``privileged pod --POD_CAN_REACH--> neighbour --RUNS_IMAGE--> image --VULNERABLE_TO--> CVE``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.pod_reachability import PodRef, pod_reach_grants
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-podlat"
_C = "arn:aws:eks:us-east-1:1:cluster/prod"
_FOOThold = f"{_C}/namespace/prod/pod/foothold"
_VICTIM = f"{_C}/namespace/prod/pod/victim"


@pytest.mark.asyncio
async def test_pod_lateral_to_vulnerable_neighbour_emerges() -> None:
    async with in_memory_semantic_store() as store:
        k8s = K8sKgWriter(store, _T)
        # the foothold is a privileged pod (source marker via record_privileged_workloads)
        await k8s.record_privileged_workloads(
            _C, [PrivilegedWorkload(namespace="prod", name="foothold", image_ref="foothold:1")]
        )
        # flat namespace → foothold can reach the victim pod
        pods = (PodRef(_FOOThold, "prod"), PodRef(_VICTIM, "prod"))
        await k8s.record_pod_reachability(pod_reach_grants(pods))
        # the victim runs a vulnerable image
        victim = await store.upsert_entity(
            tenant_id=_T, entity_type=NodeCategory.K8S_OBJECT.value, external_id=_VICTIM,
            properties={"kind": "pod"},
        )
        img = await store.upsert_entity(
            tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id="victim:1",
            properties={"kind": "container-image"},
        )
        cve = await store.upsert_entity(
            tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value, external_id="CVE-2024-77",
            properties={"severity": "CRITICAL"},
        )
        await store.add_relationship(tenant_id=_T, src_entity_id=victim, dst_entity_id=img,
                                     relationship_type=EdgeType.RUNS_IMAGE.value, properties={})
        await store.add_relationship(tenant_id=_T, src_entity_id=img, dst_entity_id=cve,
                                     relationship_type=EdgeType.VULNERABLE_TO.value, properties={})

        cands = await find_candidate_paths(store, _T)
        lateral = [c for c in cands if "POD_CAN_REACH" in c.path.edge_signature]
        assert lateral, "a pod's lateral reach to a vulnerable neighbour must surface"
        assert lateral[0].path.edge_signature == ("POD_CAN_REACH", "RUNS_IMAGE", "VULNERABLE_TO")
        assert lateral[0].path.sink_marker == "known_vulnerability"
