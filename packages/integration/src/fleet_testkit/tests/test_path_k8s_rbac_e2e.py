"""NEX-301 — K8s RBAC privilege escalation: a foothold pod → its SA → cluster-admin.

Per the NEX-203 spike, deep K8s shapes are NAMED detectors (not the generic depth-4 walker). The
``find_rbac_privilege_escalation`` detector already fires on a SA bound to a wildcard-admin role; this
proves the full chain — a privileged pod USES that SA, so compromising the pod yields cluster-admin —
and that the family is now COUNTED by the coverage harness (it was invisible via the non-traversable
BINDS edge before).
"""

import pytest
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.rbac.enumerate import Role, RoleBinding, RoleRule, Subject
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from k8s_posture.tools.privileged_pods import PrivilegedWorkload
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.coverage import measure_coverage
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "k8s-rbac"
_CLUSTER = "arn:aws:eks:us-east-1:1:cluster/prod"


@pytest.mark.asyncio
async def test_rbac_escalation_from_privileged_pod() -> None:
    async with in_memory_semantic_store() as store:
        k8s = K8sKgWriter(store, _T)
        # inventory: SA 'ci' + a wildcard-admin ClusterRole + a binding ci → admin (writes BINDS)
        await k8s.record_inventory(ClusterInventory(
            cluster_id=_CLUSTER, namespaces=("prod",),
            service_accounts=(K8sServiceAccount(name="ci", namespace="prod"),),
            roles=(Role(name="cluster-admin", kind="ClusterRole", namespace="",
                        rules=(RoleRule(api_groups=("*",), resources=("*",), verbs=("*",)),)),),
            role_bindings=(RoleBinding(name="ci-admin", kind="ClusterRoleBinding", namespace="",
                                       role_ref_kind="ClusterRole", role_ref_name="cluster-admin",
                                       subjects=(Subject(kind="ServiceAccount", name="ci", namespace="prod"),)),),
        ))
        # a privileged foothold pod runs as 'ci' (writes pod --USES_SERVICE_ACCOUNT--> SA)
        await k8s.record_privileged_workloads(
            _CLUSTER, [PrivilegedWorkload(namespace="prod", name="foothold", image_ref="img:1", service_account="ci")])

        # the named detector fires: the SA is bound to cluster-admin → RBAC escalation
        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        assert any(p.path_type == "rbac_privilege_escalation" for p in paths), \
            "SA bound to wildcard-admin must surface as rbac_privilege_escalation"

        # and it is now COUNTED by the coverage harness (was invisible via the non-traversable BINDS edge)
        report = await measure_coverage(store, _T)
        assert "rbac_privilege_escalation" in report.produced
