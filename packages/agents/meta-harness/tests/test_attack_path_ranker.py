"""The north-star surface: AttackPathRanker runs every self-seeded detector and returns
a single worst-first ranked attack-path list. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

_R = NodeCategory.CLOUD_RESOURCE.value
_ID = NodeCategory.IDENTITY.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_CVE = NodeCategory.CVE_FINDING.value


async def _node(store, t, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=t, entity_type=etype, external_id=ext, properties=props
    )


async def _edge(store, t, src, dst, rel):
    await store.add_relationship(
        tenant_id=t, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


@pytest.mark.asyncio
async def test_crown_jewel_graph_ranks_worst_first():
    """One workload that is exposed + vulnerable + assumes a role reaching SSN data lights up
    several detectors; the ranker returns them once each, crown jewel first."""
    t = "t"
    async with in_memory_semantic_store() as store:
        workload = await _node(
            store, t, _R, "arn:ecs:svc/web", {"kind": "ecs-service", "is_public": True}
        )
        image = await _node(store, t, _R, "myreg/app:1.0", {"kind": "container-image"})
        role = await _node(store, t, _ID, "arn:iam:role/task", {})
        bucket = await _node(store, t, _R, "arn:aws:s3:::secret", {"is_public": True})
        dc = await _node(store, t, _DC, "arn:aws:s3:::secret:ssn", {"data_type": "ssn"})
        cve = await _node(store, t, _CVE, "CVE-2019-19844", {"severity": "CRITICAL"})
        await _edge(store, t, workload, image, EdgeType.RUNS_IMAGE.value)
        await _edge(store, t, image, cve, EdgeType.VULNERABLE_TO.value)
        await _edge(store, t, workload, role, EdgeType.ASSUMES.value)
        await _edge(store, t, role, bucket, EdgeType.HAS_ACCESS_TO.value)
        await _edge(store, t, bucket, dc, EdgeType.EXPOSES_DATA.value)

        paths = await AttackPathRanker(KgQuery(store, t)).find_all()
        types = [p.path_type for p in paths]
        # Crown jewel (95) first; the constituent legs also surface; severities non-increasing.
        assert types[0] == "crown_jewel"
        assert "internet_exposed_vulnerable" in types
        assert "fine_grained_data" in types
        assert [p.severity for p in paths] == sorted((p.severity for p in paths), reverse=True)
        assert all(p.title and p.entities for p in paths)


@pytest.mark.asyncio
async def test_public_secret_outranks_fine_grained():
    t = "t"
    async with in_memory_semantic_store() as store:
        # A publicly-readable credential (severity 90).
        b1 = await _node(store, t, _R, "arn:aws:s3:::keys", {"is_public": True})
        d1 = await _node(store, t, _DC, "arn:aws:s3:::keys:k", {"data_type": "aws_access_key"})
        await _edge(store, t, b1, d1, EdgeType.EXPOSES_DATA.value)
        # A principal with access to public SSN data (severity 60).
        role = await _node(store, t, _ID, "arn:iam:role/r", {})
        b2 = await _node(store, t, _R, "arn:aws:s3:::pii", {"is_public": True})
        d2 = await _node(store, t, _DC, "arn:aws:s3:::pii:ssn", {"data_type": "ssn"})
        await _edge(store, t, role, b2, EdgeType.HAS_ACCESS_TO.value)
        await _edge(store, t, b2, d2, EdgeType.EXPOSES_DATA.value)

        paths = await AttackPathRanker(KgQuery(store, t)).find_all()
        assert paths[0].path_type == "public_secret"
        assert paths[0].severity > paths[-1].severity


@pytest.mark.asyncio
async def test_multiple_cves_on_one_workload_group_into_one_path():
    """A workload with several CVEs is ONE ranked path (count = N), not N rows."""
    t = "t"
    async with in_memory_semantic_store() as store:
        workload = await _node(
            store, t, _R, "arn:ecs:svc/web", {"kind": "ecs-service", "is_public": True}
        )
        image = await _node(store, t, _R, "myreg/app:1.0", {"kind": "container-image"})
        await _edge(store, t, workload, image, EdgeType.RUNS_IMAGE.value)
        for cid, sev in (("CVE-1", "HIGH"), ("CVE-2", "CRITICAL"), ("CVE-3", "LOW")):
            cve = await _node(store, t, _CVE, cid, {"severity": sev})
            await _edge(store, t, image, cve, EdgeType.VULNERABLE_TO.value)

        paths = await AttackPathRanker(KgQuery(store, t)).find_all()
        exposed = [p for p in paths if p.path_type == "internet_exposed_vulnerable"]
        assert len(exposed) == 1, "the three CVEs collapse to one path"
        assert exposed[0].count == 3
        assert set(exposed[0].evidence) == {"CVE-1", "CVE-2", "CVE-3"}
        assert "worst CRITICAL" in exposed[0].title  # worst CVE severity rolled into the title


@pytest.mark.asyncio
async def test_empty_graph_returns_no_paths():
    async with in_memory_semantic_store() as store:
        assert await AttackPathRanker(KgQuery(store, "t")).find_all() == []
