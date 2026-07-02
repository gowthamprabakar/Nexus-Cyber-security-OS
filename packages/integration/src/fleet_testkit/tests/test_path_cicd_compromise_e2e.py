"""NEX-304 e2e — CI/CD pipeline compromise (the reverse-edge problem, solved as a named detector).

Per the spike: a named detector joins the code-to-cloud chain in its NATURAL direction, so no reverse
edge / walker change is needed. Proves: a live resource DEPLOYED_VIA an IaC artifact DEFINED_IN a repo
that holds a LEAKED credential is flagged cicd_compromise (an attacker with the leaked pipeline cred can
poison the deploy). Drives the REAL appsec writer for the leaked-secret leg.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.coverage import measure_coverage
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "cicd"
_REPO = "org/infra"
_RESOURCE = "arn:aws:s3:::prod-bucket"
_ARTIFACT = f"{_REPO}:main.tf"
_AKIA = "AKIA" + "EXAMPLECICD00001"


@pytest.mark.asyncio
async def test_cicd_compromise_from_leaked_pipeline_credential() -> None:
    async with in_memory_semantic_store() as store:
        # appsec: a leaked credential lives in the repo (SECRET{leaked} --DEFINED_IN--> repo)
        await AppsecKgWriter(store, _T).record_leaked_credentials(_REPO, [_AKIA])
        # the code-to-cloud provenance: prod resource DEPLOYED_VIA an IaC artifact DEFINED_IN that repo
        res = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_RESOURCE,
            properties={},
        )
        art = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.IAC_ARTIFACT.value,
            external_id=_ARTIFACT,
            properties={},
        )
        repo = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CODE_REPOSITORY.value,
            external_id=_REPO,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=res,
            dst_entity_id=art,
            relationship_type=EdgeType.DEPLOYED_VIA.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=art,
            dst_entity_id=repo,
            relationship_type=EdgeType.DEFINED_IN.value,
            properties={},
        )

        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        cc = [p for p in paths if p.path_type == "cicd_compromise"]
        assert cc, (
            "a resource deployed from a repo with a leaked credential must be cicd_compromise"
        )
        assert "poisonable pipeline" in cc[0].title.lower()
        assert "cicd_compromise" in (await measure_coverage(store, _T)).produced
