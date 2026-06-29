"""Adversarial robustness tests for detect_toxic_combination_hypotheses + KgQuery.

ATTACK TARGETS:
  1. Crash on malformed RelatedFinding inputs   (must skip gracefully)
  2. False-negative / completeness              (must catch ALL real combos)
  3. Dedup / idempotency                        (no double TOXIC_COMBINATION nodes)
  4. Empty / boundary                           (empty inputs → empty output)

A FAILING assertion here is a REAL FINDING — do not weaken assertions to pass.
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from investigation.tools.related_findings import RelatedFinding
from investigation.toxic_combination import (
    detect_toxic_combination_hypotheses,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

TENANT = "adv-tenant-1"


def _overpriv_rf(uid: str, arn: str) -> RelatedFinding:
    """Minimal well-formed overprivilege 2004 finding."""
    return RelatedFinding(
        source_agent="identity",
        source_run_id="run-adv",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": uid, "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app", "uid": arn}],
        },
    )


async def _seed_toxic_path(store, *, principal_arn: str, bucket_arn: str) -> None:
    """Wire principal → bucket (HAS_ACCESS_TO) → data (EXPOSES_DATA)."""
    role = await store.upsert_entity(
        tenant_id=TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=principal_arn,
        properties={},
    )
    bucket = await store.upsert_entity(
        tenant_id=TENANT,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={},
    )
    data = await store.upsert_entity(
        tenant_id=TENANT,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:ssn",
        properties={},
    )
    await store.add_relationship(
        tenant_id=TENANT,
        src_entity_id=role,
        dst_entity_id=bucket,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=TENANT,
        src_entity_id=bucket,
        dst_entity_id=data,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 1 — Malformed input must NOT crash; must skip gracefully
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_malformed_missing_finding_info_no_crash():
    """RelatedFinding with no finding_info key → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={"class_uid": 2004, "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}]},
        # NOTE: finding_info is entirely absent
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "missing finding_info must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_finding_info_no_uid_no_crash():
    """finding_info present but no uid → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"types": ["overprivilege"]},  # uid missing
            "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "finding_info without uid must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_uid_explicitly_none_no_crash():
    """finding_info.uid = None explicitly → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": None, "types": ["overprivilege"]},
            "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "explicit uid=None must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_missing_affected_principals_no_crash():
    """finding_info + uid present but affected_principals key missing → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-001", "types": ["overprivilege"]},
            # affected_principals entirely absent
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "missing affected_principals must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_principal_uid_empty_string_no_crash():
    """affected_principals entry with uid='' → skip principal, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-002", "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "uid": ""}],  # empty uid
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "empty principal uid must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_principal_uid_missing_no_crash():
    """affected_principals entry with no uid key → skip principal, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-003", "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app"}],  # no uid key
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "missing principal uid key must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_empty_types_list_no_crash():
    """types is an empty list → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-004", "types": []},
            "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "empty types list must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_types_not_containing_overprivilege_no_crash():
    """types present but contains only other labels → skip, no exception."""
    rf = RelatedFinding(
        source_agent="identity",
        source_run_id="r",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-005", "types": ["dormant", "unused-permission"]},
            "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
        },
    )
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[rf]
        )
    assert hyps == (), "types without overprivilege must produce no hypotheses"


@pytest.mark.asyncio
async def test_malformed_wrong_class_uid_skipped_valid_one_fires():
    """Mix of class_uid 2003 (wrong) + 2004 valid finding → only valid one fires."""
    arn = "arn:aws:iam::1:role/adv-app"
    bucket = "arn:aws:s3:::adv-pii"

    wrong_class = RelatedFinding(
        source_agent="cloud_posture",
        source_run_id="r",
        class_uid=2003,  # wrong class — must be ignored
        payload={
            "class_uid": 2003,
            "finding_info": {"uid": "CP-001", "types": ["overprivilege"]},
            "affected_principals": [{"uid": arn}],
        },
    )
    valid = _overpriv_rf("IDENT-006", arn)

    async with in_memory_semantic_store() as store:
        await _seed_toxic_path(store, principal_arn=arn, bucket_arn=bucket)
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[wrong_class, valid],
        )

    assert len(hyps) == 1, f"expected exactly 1 hypothesis, got {len(hyps)}"
    assert hyps[0].evidence_refs == ("finding:IDENT-006",), (
        "evidence ref must cite the 2004 finding"
    )


@pytest.mark.asyncio
async def test_malformed_all_bad_one_good_only_good_fires():
    """Gauntlet: 7 malformed + 1 well-formed → exactly 1 hypothesis, no crash."""
    arn = "arn:aws:iam::1:role/adv-gauntlet"
    bucket = "arn:aws:s3:::adv-gauntlet-pii"
    bad_rfs: list[RelatedFinding] = [
        # no finding_info
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={"affected_principals": [{"uid": arn}]},
        ),
        # uid missing
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"types": ["overprivilege"]},
                "affected_principals": [{"uid": arn}],
            },
        ),
        # uid = None
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"uid": None, "types": ["overprivilege"]},
                "affected_principals": [{"uid": arn}],
            },
        ),
        # empty uid
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"uid": "u", "types": ["overprivilege"]},
                "affected_principals": [{"uid": ""}],
            },
        ),
        # empty types
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"uid": "u2", "types": []},
                "affected_principals": [{"uid": arn}],
            },
        ),
        # wrong type label
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"uid": "u3", "types": ["dormant"]},
                "affected_principals": [{"uid": arn}],
            },
        ),
        # wrong class_uid
        RelatedFinding(
            source_agent="id",
            source_run_id="r",
            class_uid=2003,
            payload={
                "finding_info": {"uid": "u4", "types": ["overprivilege"]},
                "affected_principals": [{"uid": arn}],
            },
        ),
    ]
    good_rf = _overpriv_rf("GAUNTLET-GOOD", arn)

    async with in_memory_semantic_store() as store:
        await _seed_toxic_path(store, principal_arn=arn, bucket_arn=bucket)
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[*bad_rfs, good_rf],
        )

    assert len(hyps) == 1, f"gauntlet: expected 1 hypothesis, got {len(hyps)}"
    assert hyps[0].evidence_refs == ("finding:GAUNTLET-GOOD",)


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 2 — False-negative / completeness
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_completeness_three_distinct_principals_three_hypotheses():
    """3 distinct principals x 3 distinct buckets -> exactly 3 hypotheses."""
    principals = [f"arn:aws:iam::1:role/p{i}" for i in range(3)]
    buckets = [f"arn:aws:s3:::bucket-{i}" for i in range(3)]
    findings = [_overpriv_rf(f"FID-{i}", principals[i]) for i in range(3)]

    async with in_memory_semantic_store() as store:
        for p, b in zip(principals, buckets, strict=False):
            await _seed_toxic_path(store, principal_arn=p, bucket_arn=b)

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=findings
        )

    assert len(hyps) == 3, f"expected 3 hypotheses for 3 principals, got {len(hyps)}"

    # Each hypothesis must cite its own finding uid
    evidence_refs = {h.evidence_refs[0] for h in hyps}
    assert evidence_refs == {"finding:FID-0", "finding:FID-1", "finding:FID-2"}


@pytest.mark.asyncio
async def test_completeness_one_principal_two_buckets_two_hypotheses():
    """One principal with HAS_ACCESS_TO TWO distinct public+PII buckets → 2 hypotheses."""
    arn = "arn:aws:iam::1:role/greedy"
    buckets = ["arn:aws:s3:::greedy-bucket-a", "arn:aws:s3:::greedy-bucket-b"]

    async with in_memory_semantic_store() as store:
        for b in buckets:
            await _seed_toxic_path(store, principal_arn=arn, bucket_arn=b)

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[_overpriv_rf("GREEDY-FINDING", arn)],
        )

    assert len(hyps) == 2, f"one principal → 2 buckets must yield 2 hypotheses, got {len(hyps)}"

    # Both hypotheses must share the same evidence ref (the one finding that named the principal)
    for h in hyps:
        assert h.evidence_refs == ("finding:GREEDY-FINDING",), (
            "both hypotheses must cite the seeding finding"
        )


@pytest.mark.asyncio
async def test_completeness_two_principals_same_bucket_two_hypotheses():
    """Two principals both reaching the SAME public+PII bucket → 2 hypotheses (one per principal)."""
    p1 = "arn:aws:iam::1:role/alpha"
    p2 = "arn:aws:iam::1:role/beta"
    bucket = "arn:aws:s3:::shared-bucket"

    # Manually seed: both principals → shared bucket → shared data
    async with in_memory_semantic_store() as store:
        r1 = await store.upsert_entity(
            tenant_id=TENANT, entity_type=NodeCategory.IDENTITY.value, external_id=p1, properties={}
        )
        r2 = await store.upsert_entity(
            tenant_id=TENANT, entity_type=NodeCategory.IDENTITY.value, external_id=p2, properties={}
        )
        bkt = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=bucket,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{bucket}:ssn",
            properties={},
        )
        for role_id in (r1, r2):
            await store.add_relationship(
                tenant_id=TENANT,
                src_entity_id=role_id,
                dst_entity_id=bkt,
                relationship_type=EdgeType.HAS_ACCESS_TO.value,
                properties={},
            )
        await store.add_relationship(
            tenant_id=TENANT,
            src_entity_id=bkt,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[
                _overpriv_rf("ALPHA-FID", p1),
                _overpriv_rf("BETA-FID", p2),
            ],
        )

    assert len(hyps) == 2, f"2 principals → same bucket must yield 2 hypotheses, got {len(hyps)}"

    refs = {h.evidence_refs[0] for h in hyps}
    assert refs == {"finding:ALPHA-FID", "finding:BETA-FID"}, (
        "each hypothesis must cite its own principal's finding"
    )


@pytest.mark.asyncio
async def test_completeness_evidence_ref_cites_correct_finding_uid():
    """Verify evidence_refs tie back correctly to the specific finding that introduced each principal."""
    p1 = "arn:aws:iam::1:role/eve"
    p2 = "arn:aws:iam::1:role/mallory"
    bucket_1 = "arn:aws:s3:::eve-bucket"
    bucket_2 = "arn:aws:s3:::mallory-bucket"

    async with in_memory_semantic_store() as store:
        await _seed_toxic_path(store, principal_arn=p1, bucket_arn=bucket_1)
        await _seed_toxic_path(store, principal_arn=p2, bucket_arn=bucket_2)

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[
                _overpriv_rf("EVE-UID-123", p1),
                _overpriv_rf("MALLORY-UID-456", p2),
            ],
        )

    assert len(hyps) == 2
    refs_by_hyp = {h.hypothesis_id: h.evidence_refs[0] for h in hyps}

    # Both evidence refs must be present
    assert "finding:EVE-UID-123" in refs_by_hyp.values(), "EVE finding not cited"
    assert "finding:MALLORY-UID-456" in refs_by_hyp.values(), "MALLORY finding not cited"


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 3 — Dedup / idempotency
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dedup_double_call_does_not_double_toxic_nodes():
    """Calling detect twice on same store+inputs must NOT double TOXIC_COMBINATION nodes."""
    arn = "arn:aws:iam::1:role/idempotent"
    bucket = "arn:aws:s3:::idempotent-pii"
    finding = _overpriv_rf("IDEMP-UID", arn)

    async with in_memory_semantic_store() as store:
        await _seed_toxic_path(store, principal_arn=arn, bucket_arn=bucket)

        hyps1 = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[finding]
        )
        hyps2 = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[finding]
        )

        toxic_nodes = await store.list_entities_by_type(
            tenant_id=TENANT, entity_type=NodeCategory.TOXIC_COMBINATION.value
        )

    assert len(hyps1) == 1, "first call must yield 1 hypothesis"
    assert len(hyps2) == 1, "second call must yield 1 hypothesis"
    assert len(toxic_nodes) == 1, (
        f"IDEMPOTENCY FAILURE: expected 1 TOXIC_COMBINATION node after 2 calls, "
        f"found {len(toxic_nodes)} — _combo_external_id dedup is broken"
    )


@pytest.mark.asyncio
async def test_dedup_same_combo_from_two_different_finding_uids():
    """Same principal cited by TWO different overprivilege findings (different uids).

    The detector's `ref_by_principal.setdefault` keeps the FIRST finding uid for a
    given entity_id. This means only ONE hypothesis is produced for the toxic path
    (one per combo, not one per finding). This test asserts and documents that
    behaviour — if a future change makes it produce TWO hypotheses (one per finding),
    that may be a semantic improvement but it would also be a CHANGE in contract.
    """
    arn = "arn:aws:iam::1:role/double-cited"
    bucket = "arn:aws:s3:::double-cited-pii"

    # Two distinct findings, same ARN
    f1 = _overpriv_rf("FIRST-FID", arn)
    f2 = _overpriv_rf("SECOND-FID", arn)

    async with in_memory_semantic_store() as store:
        await _seed_toxic_path(store, principal_arn=arn, bucket_arn=bucket)

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[f1, f2],
        )

    # The setdefault means first-wins: only 1 hypothesis, citing FIRST-FID
    assert len(hyps) == 1, (
        f"CONTRACT: same principal via 2 findings must produce exactly 1 hypothesis "
        f"(first-wins setdefault). Got {len(hyps)}. If 2, the behaviour changed."
    )
    assert hyps[0].evidence_refs == ("finding:FIRST-FID",), (
        "first-wins: evidence ref must cite the FIRST finding, not the second"
    )


@pytest.mark.asyncio
async def test_dedup_multi_principal_same_combo_no_duplicate_toxic_nodes():
    """Two principals both reach the SAME bucket+data — 2 combos, 2 TOXIC_COMBINATION nodes
    (different external ids because principal differs), NOT duplicated by double-call."""
    p1 = "arn:aws:iam::1:role/dup-p1"
    p2 = "arn:aws:iam::1:role/dup-p2"
    bucket = "arn:aws:s3:::dup-shared"

    async with in_memory_semantic_store() as store:
        r1 = await store.upsert_entity(
            tenant_id=TENANT, entity_type=NodeCategory.IDENTITY.value, external_id=p1, properties={}
        )
        r2 = await store.upsert_entity(
            tenant_id=TENANT, entity_type=NodeCategory.IDENTITY.value, external_id=p2, properties={}
        )
        bkt = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=bucket,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{bucket}:ssn",
            properties={},
        )
        for role_id in (r1, r2):
            await store.add_relationship(
                tenant_id=TENANT,
                src_entity_id=role_id,
                dst_entity_id=bkt,
                relationship_type=EdgeType.HAS_ACCESS_TO.value,
                properties={},
            )
        await store.add_relationship(
            tenant_id=TENANT,
            src_entity_id=bkt,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[_overpriv_rf("P1-FID", p1), _overpriv_rf("P2-FID", p2)],
        )

        # Call again — count must not grow
        await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[_overpriv_rf("P1-FID", p1), _overpriv_rf("P2-FID", p2)],
        )

        toxic_nodes = await store.list_entities_by_type(
            tenant_id=TENANT, entity_type=NodeCategory.TOXIC_COMBINATION.value
        )

    assert len(hyps) == 2, f"expected 2 hypotheses (one per principal), got {len(hyps)}"
    assert len(toxic_nodes) == 2, (
        f"IDEMPOTENCY: 2 distinct combos should create exactly 2 nodes. "
        f"After double-call found {len(toxic_nodes)}."
    )


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 4 — Empty / boundary
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_boundary_empty_related_findings_returns_empty_tuple():
    """Empty related_findings list → () with no crash."""
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=[]
        )
    assert hyps == (), f"empty input must return (), got {hyps!r}"


@pytest.mark.asyncio
async def test_boundary_valid_overprivilege_but_no_graph_edges_returns_empty():
    """Valid overprivilege finding but the principal has NO graph edges at all → ()."""
    arn = "arn:aws:iam::1:role/ghost"
    # Do NOT seed any edges — principal node may or may not exist yet
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[_overpriv_rf("GHOST-FID", arn)],
        )
    assert hyps == (), "valid finding but empty graph must produce no hypotheses"


@pytest.mark.asyncio
async def test_boundary_has_access_to_but_no_exposes_data_returns_empty():
    """Principal → bucket exists (HAS_ACCESS_TO) but bucket has no EXPOSES_DATA edge → ()."""
    arn = "arn:aws:iam::1:role/half-path"
    bucket = "arn:aws:s3:::half-path-bucket"

    async with in_memory_semantic_store() as store:
        role = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.IDENTITY.value,
            external_id=arn,
            properties={},
        )
        bkt = await store.upsert_entity(
            tenant_id=TENANT,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=bucket,
            properties={},
        )
        # Only HAS_ACCESS_TO — no EXPOSES_DATA
        await store.add_relationship(
            tenant_id=TENANT,
            src_entity_id=role,
            dst_entity_id=bkt,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )

        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id=TENANT,
            related_findings=[_overpriv_rf("HALF-PATH-FID", arn)],
        )

    assert hyps == (), "incomplete path (no EXPOSES_DATA) must produce no hypotheses"


@pytest.mark.asyncio
async def test_boundary_only_non_2004_findings_all_skipped():
    """A mix of class_uid 2001, 2002, 2003, 2005, 2006 — none 2004 → ()."""
    wrong_classes = [2001, 2002, 2003, 2005, 2006]
    rfs = [
        RelatedFinding(
            source_agent="agent",
            source_run_id="r",
            class_uid=cls,
            payload={
                "class_uid": cls,
                "finding_info": {"uid": f"F-{cls}", "types": ["overprivilege"]},
                "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
            },
        )
        for cls in wrong_classes
    ]
    async with in_memory_semantic_store() as store:
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id=TENANT, related_findings=rfs
        )
    assert hyps == (), "non-2004 findings must all be skipped"
