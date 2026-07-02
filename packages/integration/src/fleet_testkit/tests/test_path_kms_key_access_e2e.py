"""NEX-202a e2e — reaching a KMS key that protects data is a distinct attack path.

Per the NEX-202 spike: a KMS key's impact is modelled as EXPOSES_DATA (no new sink/walker). Drives the
REAL writers (cloud-posture record_kms_protected_data + identity access) and proves the distinct
`kms_key_access` family: ``principal --HAS_ACCESS_TO--> kms-key --EXPOSES_DATA--> data`` → the principal
can decrypt the crown data. Also proves the family now counts in coverage.
"""

import pytest
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudKgWriter
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.coverage import measure_coverage
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "kms-access"
_KEY = "arn:aws:kms:us-east-1:1:key/crown"
_ROLE = "arn:aws:iam::1:role/app"


@pytest.mark.asyncio
async def test_kms_key_access_is_a_distinct_path_and_counts() -> None:
    async with in_memory_semantic_store() as store:
        # the KMS key protects sensitive data (cloud-posture, the spike reframe)
        await CloudKgWriter(store, _T).record_kms_protected_data([(_KEY, "ssn")])
        # a role can use the key
        await IdentityKgWriter(store, _T).record_access([(_ROLE, _KEY)])

        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        kms = [p for p in paths if p.path_type == "kms_key_access"]
        assert kms, "access to a data-protecting KMS key must be a distinct kms_key_access path"
        assert "decrypt" in kms[0].title.lower()
        # not double-reported as a bare fine_grained_data leg (subsumption)
        assert not any(p.path_type == "fine_grained_data" and _KEY in p.title for p in paths)
        # and it counts in coverage
        assert "kms_key_access" in (await measure_coverage(store, _T)).produced
