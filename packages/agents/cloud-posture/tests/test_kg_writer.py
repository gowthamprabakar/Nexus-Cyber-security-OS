"""Mocked unit tests for the SemanticStore-backed `KnowledgeGraphWriter`.

Task 4 of the KG-loop-closure plan
(`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`).

Covers four shapes of invariant the writer claims to preserve:

1. **Per-method upsert payload shape** — `upsert_asset` calls
   `SemanticStore.upsert_entity` with `entity_type="asset"`, `kind`
   moved from MERGE key (Cypher) to property; `upsert_finding` does
   the same with `entity_type="finding"`. `tenant_id` propagates from
   the writer's `customer_id` on every substrate call.

2. **AFFECTS-edge dedup per-finding** — the writer's load-bearing
   correctness claim. Calling `upsert_finding` twice with the same
   `(finding_id, arn)` pair within one writer instance produces
   exactly ONE `add_relationship` call. The same arn against a
   different finding is NOT deduped (per-finding scope, not global).
   Duplicate arns within ONE `affected_arns` list also dedup. This
   is what compensates for `SemanticStore.add_relationship` being
   INSERT-only. The cross-RUN duplicate-edge case is consciously
   accepted v0.1 debt — surfaced in the Task 8 verification record;
   Task 6's live proof asserts the within-run case end-to-end.

3. **Empty-affected-arns is a no-op for relationships** — the
   finding entity is upserted, but no AFFECTS edges land.

4. **Entity-id round-trip** — `upsert_entity` returns ids that the
   writer uses verbatim as the `src_entity_id` / `dst_entity_id` of
   `add_relationship`. If the substrate ever returns different ids
   for the same `(tenant_id, type, external_id)` it would silently
   point the AFFECTS edge at the wrong nodes — this test pins that.

No live Postgres; pure mocked `SemanticStore`. The mock's
`upsert_entity` memoizes returned ids by `(entity_type, external_id)`
so the writer's idempotency assumption (same key ⇒ same id) holds
end-to-end through the test, exactly as the real substrate behaves.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory import SemanticStore
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter


def _make_semantic_store() -> SemanticStore:
    """Return an `AsyncMock(spec=SemanticStore)` that behaves like the real thing.

    `upsert_entity` returns deterministic entity_ids memoized by
    `(entity_type, external_id)` — same key, same id — matching the
    substrate's `(tenant_id, type, external_id)` idempotency. (Tests
    here use one tenant per test, so `(type, external_id)` suffices
    as the cache key.) `add_relationship` returns a monotonically
    increasing integer as its synthetic `relationship_id`.
    """
    entity_ids: dict[tuple[str, str], str] = {}
    rel_counter = {"n": 0}

    async def fake_upsert_entity(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id, properties
        key = (entity_type, external_id)
        if key not in entity_ids:
            entity_ids[key] = f"ent_{entity_type}_{len(entity_ids)}"
        return entity_ids[key]

    async def fake_add_relationship(
        *,
        tenant_id: str,
        src_entity_id: str,
        dst_entity_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> int:
        del tenant_id, src_entity_id, dst_entity_id, relationship_type, properties
        rel_counter["n"] += 1
        return rel_counter["n"]

    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.side_effect = fake_upsert_entity
    store.add_relationship.side_effect = fake_add_relationship
    return cast(SemanticStore, store)


# ----------------------------- payload shape --------------------------------


@pytest.mark.asyncio
async def test_upsert_asset_calls_upsert_entity_with_asset_type() -> None:
    """`upsert_asset` invokes `SemanticStore.upsert_entity` with `entity_type="asset"`."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_asset(
        kind="aws_s3_bucket",
        external_id="arn:aws:s3:::alpha",
        properties={"region": "us-east-1"},
    )

    store_mock = cast(AsyncMock, store)
    store_mock.upsert_entity.assert_awaited_once()
    kwargs = store_mock.upsert_entity.call_args.kwargs
    assert kwargs["tenant_id"] == "cust_test"
    assert kwargs["entity_type"] == "asset"
    assert kwargs["external_id"] == "arn:aws:s3:::alpha"


@pytest.mark.asyncio
async def test_upsert_asset_moves_kind_from_key_to_property() -> None:
    """Cypher had `kind` as a MERGE key; SemanticStore folds it into properties."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_asset(
        kind="aws_iam_user",
        external_id="arn:aws:iam::111122223333:user/alice",
        properties={"account_uid": "111122223333"},
    )

    props = cast(AsyncMock, store).upsert_entity.call_args.kwargs["properties"]
    assert props["kind"] == "aws_iam_user"
    assert props["account_uid"] == "111122223333"


@pytest.mark.asyncio
async def test_upsert_asset_handles_empty_properties_dict() -> None:
    """Empty caller-provided properties still carry `kind` in the substrate payload."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_asset(kind="aws_kms_key", external_id="key-abc", properties={})

    props = cast(AsyncMock, store).upsert_entity.call_args.kwargs["properties"]
    assert props == {"kind": "aws_kms_key"}


@pytest.mark.asyncio
async def test_upsert_finding_calls_upsert_entity_with_finding_type() -> None:
    """`upsert_finding` invokes `upsert_entity` with `entity_type="finding"`."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=[],
    )

    store_mock = cast(AsyncMock, store)
    store_mock.upsert_entity.assert_awaited_once()
    kwargs = store_mock.upsert_entity.call_args.kwargs
    assert kwargs["tenant_id"] == "cust_test"
    assert kwargs["entity_type"] == "finding"
    assert kwargs["external_id"] == "CSPM-AWS-S3-001-alpha"
    assert kwargs["properties"] == {"rule_id": "CSPM-AWS-S3-001", "severity": "high"}


# ----------------------------- empty-arns no-op -----------------------------


@pytest.mark.asyncio
async def test_upsert_finding_with_empty_affected_arns_writes_no_relationships() -> None:
    """No arns ⇒ the finding entity is written, but `add_relationship` never fires."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-ORG-001-x",
        rule_id="CSPM-AWS-ORG-001",
        severity="medium",
        affected_arns=[],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.upsert_entity.await_count == 1  # finding only
    store_mock.add_relationship.assert_not_called()


# ----------------------------- AFFECTS plumbing -----------------------------


@pytest.mark.asyncio
async def test_upsert_finding_relates_each_affected_arn_to_finding() -> None:
    """N arns ⇒ `upsert_entity` N+1 times (1 finding + N assets); `add_relationship` N times."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-IAM-002-foo",
        rule_id="CSPM-AWS-IAM-002",
        severity="critical",
        affected_arns=[
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:iam::123456789012:user/bob",
        ],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.upsert_entity.await_count == 3  # 1 finding + 2 assets
    assert store_mock.add_relationship.await_count == 2

    rel_kwargs = [c.kwargs for c in store_mock.add_relationship.await_args_list]
    assert all(r["tenant_id"] == "cust_test" for r in rel_kwargs)
    assert all(r["relationship_type"] == "AFFECTS" for r in rel_kwargs)


@pytest.mark.asyncio
async def test_upsert_finding_uses_returned_entity_ids_as_relationship_src_and_dst() -> None:
    """The ids `upsert_entity` returns ARE the src/dst the AFFECTS edge points at.

    Mismatch here would silently point the edge at unrelated nodes — the
    one bug agent-level mocking can't catch in any of the other tests.
    """
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha"],
    )

    store_mock = cast(AsyncMock, store)
    # The mock returns "ent_finding_0" for the first upsert (the finding)
    # and "ent_asset_1" for the second (the affected S3 bucket).
    rel_kwargs = store_mock.add_relationship.await_args_list[0].kwargs
    assert rel_kwargs["src_entity_id"] == "ent_finding_0"
    assert rel_kwargs["dst_entity_id"] == "ent_asset_1"


# ----------------------------- the load-bearing dedup -----------------------


@pytest.mark.asyncio
async def test_dedup_collapses_same_finding_same_arn_across_two_calls() -> None:
    """Calling `upsert_finding` twice with the same arn ⇒ ONE `add_relationship` call.

    This is what compensates for `SemanticStore.add_relationship` being
    INSERT-only. Within ONE writer instance the dedup table prevents the
    second visit from emitting a duplicate AFFECTS row. Task 6's live
    proof asserts the same invariant against real Postgres.
    """
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha"],
    )
    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha"],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.add_relationship.await_count == 1


@pytest.mark.asyncio
async def test_dedup_within_one_call_collapses_duplicate_arns_in_the_list() -> None:
    """`affected_arns=[arn, arn]` in one call ⇒ ONE `add_relationship`, not two.

    The dedup table is consulted per-arn, not per-call, so identical
    entries inside a single `affected_arns` list also collapse.
    """
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha", "arn:aws:s3:::alpha"],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.add_relationship.await_count == 1


@pytest.mark.asyncio
async def test_dedup_does_not_collapse_same_arn_across_different_findings() -> None:
    """Per-finding scope: finding A → arn X and finding B → arn X BOTH fire.

    The dedup table is keyed by `finding_id`. Two different findings
    pointing at the same asset are two separate AFFECTS edges, and
    BOTH must land in the graph.
    """
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::shared"],
    )
    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-002-alpha",
        rule_id="CSPM-AWS-S3-002",
        severity="medium",
        affected_arns=["arn:aws:s3:::shared"],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.add_relationship.await_count == 2


@pytest.mark.asyncio
async def test_dedup_continues_to_accept_new_arns_for_same_finding() -> None:
    """First call: finding ↔ arn A. Second call: finding ↔ {A, B}. Net effect: A once, B once."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-IAM-002-foo",
        rule_id="CSPM-AWS-IAM-002",
        severity="critical",
        affected_arns=["arn:aws:iam::123456789012:user/alice"],
    )
    await writer.upsert_finding(
        finding_id="CSPM-AWS-IAM-002-foo",
        rule_id="CSPM-AWS-IAM-002",
        severity="critical",
        affected_arns=[
            "arn:aws:iam::123456789012:user/alice",  # already related — dedup
            "arn:aws:iam::123456789012:user/bob",  # new — relate
        ],
    )

    store_mock = cast(AsyncMock, store)
    assert store_mock.add_relationship.await_count == 2  # alice (1st call) + bob (2nd call)


# ----------------------------- tenant propagation ---------------------------


@pytest.mark.asyncio
async def test_tenant_id_propagates_to_every_substrate_call() -> None:
    """`customer_id` flows through as `tenant_id` on every substrate write."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(semantic_store=store, customer_id="cust_acme")

    await writer.upsert_asset(kind="aws_s3_bucket", external_id="b1", properties={})
    await writer.upsert_finding(
        finding_id="rule-1-b1",
        rule_id="rule-1",
        severity="high",
        affected_arns=["b1"],
    )

    store_mock = cast(AsyncMock, store)
    for call in store_mock.upsert_entity.await_args_list:
        assert call.kwargs["tenant_id"] == "cust_acme"
    for call in store_mock.add_relationship.await_args_list:
        assert call.kwargs["tenant_id"] == "cust_acme"
