"""Cross-domain path A3 — live resource deployed from misconfigured IaC, REAL e2e.

The third cross-domain path (code-to-cloud): cloud-posture + appsec. Drives both feeders' REAL
writers, runs the REAL correlation resolver (``link_deployed_via`` → ``DEPLOYED_VIA``), and asserts
the code-to-cloud detector fires:

- cloud-posture's REAL EC2 reader records a moto instance carrying a ``nexus:iac`` provenance tag.
- appsec's REAL ``record`` writes the ``IAC_ARTIFACT`` node (written ONLY for a misconfigured IaC
  file) + its ``DEFINED_IN`` repo.
- ``correlate_all`` writes ``DEPLOYED_VIA`` (resource → IaC artifact) where the provenance matches.
- ``AttackPathRanker`` surfaces "Misconfigured IaC deployed"; an untagged resource or an IaC
  misconfig with no deployed resource stays dark.

Hermetic: the instance is moto-REAL; the repo/IaC inputs are appsec's native parsed types.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.correlation import correlate_all
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.appsec_kit import drive_appsec_iac
from fleet_testkit.moto_aws import drive_ec2_workloads, moto_all_clients, setup_ec2_instance

_TENANT = "tenant-c2c"
_MISCONFIG = ("github", "acme", "infra", "main.tf")  # host, owner, name, file
_ARTIFACT = "github/acme/infra:main.tf"  # the IAC_ARTIFACT external_id this deploys


async def _seed_instance(store, *, iac_artifact: str) -> None:
    with moto_all_clients(()) as (_s3, iam, _ecs, ec2):
        setup_ec2_instance(ec2, name="web", iac_artifact=iac_artifact)
        workloads = await drive_ec2_workloads(
            store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
        )
    assert workloads and workloads[0].iac_artifact == iac_artifact


@pytest.mark.asyncio
async def test_resource_from_misconfigured_iac_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        artifacts = await drive_appsec_iac(store, tenant_id=_TENANT, misconfigs=(_MISCONFIG,))
        assert artifacts == [_ARTIFACT]
        await _seed_instance(store, iac_artifact=_ARTIFACT)

        await correlate_all(store, _TENANT)  # writes DEPLOYED_VIA (resource → IaC artifact)

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        hits = [p for p in paths if p.path_type == "iac_misconfig_deployed"]
        assert len(hits) == 1, "a resource deployed from misconfigured IaC surfaces one path"
        assert hits[0].evidence == (_ARTIFACT,)
        assert hits[0].severity == 58


@pytest.mark.asyncio
async def test_untagged_resource_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        await drive_appsec_iac(store, tenant_id=_TENANT, misconfigs=(_MISCONFIG,))
        await _seed_instance(store, iac_artifact="")  # no provenance tag → no DEPLOYED_VIA
        await correlate_all(store, _TENANT)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "iac_misconfig_deployed"]


@pytest.mark.asyncio
async def test_iac_misconfig_without_deployed_resource_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        # The IaC misconfig exists, but no live resource references it.
        await drive_appsec_iac(store, tenant_id=_TENANT, misconfigs=(_MISCONFIG,))
        await correlate_all(store, _TENANT)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "iac_misconfig_deployed"]
