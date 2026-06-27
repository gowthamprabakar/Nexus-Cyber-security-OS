"""B5 proof — the confirmed (named) and candidate (generic) tiers coexist and stay separated.

Drives a real scene with both a NAMED path (a public bucket exposing a secret → public_secret) and a
deliberately-UNNAMED novel path (a runtime detection on a host that reaches sensitive data — a
(runtime_detection → sensitive_data) combination no named detector covers). Asserts the confirmed
tier reports the named one and the candidate tier surfaces ONLY the novel one (never the
named-covered duplicate). This is the whole hybrid thesis, end to end.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.attack_path_report import render_candidates
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_scene_clients
from fleet_testkit.runtime_events import drive_runtime_findings

_TENANT = "tenant-tiers"
_AWS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"


@pytest.mark.asyncio
async def test_confirmed_and_candidate_tiers_coexist_and_separate() -> None:
    async with in_memory_semantic_store() as store:
        # CONFIRMED (named): a public bucket exposing an AWS key → public_secret.
        buckets = (MotoBucket("acme-creds", public=True, encrypted=True, objects={"k": _AWS_KEY}),)
        with moto_scene_clients(buckets) as (s3, _iam, _sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)

        # CANDIDATE (novel, deliberately unnamed): a runtime detection on a host that reaches data.
        await drive_runtime_findings(store, tenant_id=_TENANT, workloads=(("host-1", "img:1.0"),))
        rows = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        host = next(r for r in rows if r.external_id == "host-1")
        data = await store.upsert_entity(
            tenant_id=_TENANT,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="host-1:ssn",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_TENANT,
            src_entity_id=host.entity_id,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # The confirmed tier reports the named finding.
        confirmed = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert "public_secret" in {p.path_type for p in confirmed}

        # The candidate tier surfaces ONLY the novel combination, never the named-covered duplicate.
        candidates = await find_candidate_paths(store, _TENANT)
        pairs = {c.pair for c in candidates}
        assert ("runtime_detection", "sensitive_data") in pairs
        assert ("public_resource", "sensitive_data") not in pairs

        # Every candidate is scored below every confirmed finding (the cap holds end-to-end).
        worst_confirmed = min(p.severity for p in confirmed)
        assert all(c.score < worst_confirmed for c in candidates)

        report = render_candidates(candidates, tenant_id=_TENANT)
        assert "UNVERIFIED" in report
        assert "runtime_detection -> sensitive_data" in report
