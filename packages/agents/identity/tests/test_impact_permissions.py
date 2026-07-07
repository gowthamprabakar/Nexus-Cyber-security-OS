"""Cycle 8 Task 2 — _has_destructive_permissions detection + writer + agent wiring.

Tests:
1. test_destructive_kms_delete_detected — role with kms:ScheduleKeyDeletion on * → True.
2. test_read_only_not_destructive — role with only kms:Decrypt / s3:GetObject → False.
3. test_boundary_caps_destructive — destructive action allowed in policy but boundary denies → False.
4. test_s3_put_bucket_policy_detected — s3:PutBucketPolicy → True.
5. test_s3_delete_wildcard_detected — s3:Delete* → True.
6. test_record_destructive_principals_writer — writer sets destructive_permissions=True on node.
"""

from __future__ import annotations

from typing import Any

import pytest
from identity.agent import _has_destructive_permissions

_ACCT = "123456789012"


def _doc(statements: list[tuple[object, object]]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": a, "Resource": r} for a, r in statements],
    }


def _deny_doc(actions: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }


def _boundary_doc(actions: list[str]) -> dict[str, Any]:
    """A permission-boundary document that allows ONLY the given actions."""
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": a, "Resource": "*"} for a in actions],
    }


# ---------------------------------------------------------------------------
# Detection helper unit tests
# ---------------------------------------------------------------------------


def test_destructive_kms_delete_detected() -> None:
    """A role with kms:ScheduleKeyDeletion on * must return True."""
    docs = [_doc([("kms:ScheduleKeyDeletion", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_destructive_kms_disable_detected() -> None:
    """A role with kms:DisableKey on * must return True."""
    docs = [_doc([("kms:DisableKey", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_destructive_kms_delete_imported_detected() -> None:
    """A role with kms:DeleteImportedKeyMaterial on * must return True."""
    docs = [_doc([("kms:DeleteImportedKeyMaterial", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_s3_put_bucket_policy_detected() -> None:
    """s3:PutBucketPolicy is destructive (can rewrite access to ransom/exfil)."""
    docs = [_doc([("s3:PutBucketPolicy", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_s3_delete_wildcard_detected() -> None:
    """s3:Delete* wildcard (matches s3:DeleteObject, s3:DeleteBucket, etc.) → True."""
    docs = [_doc([("s3:Delete*", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_s3_delete_object_detected() -> None:
    """s3:DeleteObject on * → True."""
    docs = [_doc([("s3:DeleteObject", "*")])]
    assert _has_destructive_permissions(docs, None) is True


def test_read_only_not_destructive() -> None:
    """A role with only kms:Decrypt + s3:GetObject must return False."""
    docs = [_doc([("kms:Decrypt", "*"), ("s3:GetObject", "*")])]
    assert _has_destructive_permissions(docs, None) is False


def test_empty_documents_not_destructive() -> None:
    """No documents → no grants → False."""
    assert _has_destructive_permissions([], None) is False


def test_boundary_caps_destructive() -> None:
    """Destructive action in policy, but boundary does NOT allow it → False (boundary cap).

    The permission-boundary only allows s3:GetObject.  _boundary_allows_action returns False
    for kms:ScheduleKeyDeletion → _granted_capped returns None → helper returns False.
    """
    docs = [_doc([("kms:ScheduleKeyDeletion", "*")])]
    boundary = _boundary_doc(["s3:GetObject"])  # boundary only allows reads — no delete/disable
    assert _has_destructive_permissions(docs, boundary) is False


def test_boundary_with_matching_action_not_capped() -> None:
    """Destructive action in policy AND boundary allows it → True (not capped)."""
    docs = [_doc([("kms:DisableKey", "*")])]
    boundary = _boundary_doc(["kms:DisableKey"])
    assert _has_destructive_permissions(docs, boundary) is True


def test_wildcard_admin_policy_is_destructive() -> None:
    """An admin wildcard policy (Action=*) grants all destructive actions → True."""
    docs = [_doc([("*", "*")])]
    assert _has_destructive_permissions(docs, None) is True


# ---------------------------------------------------------------------------
# Writer test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_destructive_principals_sets_property() -> None:
    """record_destructive_principals upserts IDENTITY node with destructive_permissions=True."""
    from charter.memory.graph_types import NodeCategory
    from fleet_testkit import in_memory_semantic_store
    from identity.kg_writer import KnowledgeGraphWriter

    arn = f"arn:aws:iam::{_ACCT}:role/destroyer"
    async with in_memory_semantic_store() as store:
        writer = KnowledgeGraphWriter(store, "tenant-dt")
        await writer.record_destructive_principals([arn])

        # The node must exist with destructive_permissions=True.
        identities = await store.list_entities_by_type(
            tenant_id="tenant-dt", entity_type=NodeCategory.IDENTITY.value
        )
        assert len(identities) == 1
        node = identities[0]
        assert node.external_id == arn
        assert node.properties.get("destructive_permissions") is True


@pytest.mark.asyncio
async def test_record_destructive_principals_merges_existing_props() -> None:
    """record_destructive_principals must not clobber existing node properties (name/type)."""
    from charter.memory.graph_types import NodeCategory
    from fleet_testkit import in_memory_semantic_store
    from identity.kg_writer import KnowledgeGraphWriter

    arn = f"arn:aws:iam::{_ACCT}:role/destroyer2"
    async with in_memory_semantic_store() as store:
        writer = KnowledgeGraphWriter(store, "tenant-dt2")
        # First, write the node with name + principal_type (as record_listing does).
        await writer.upsert_node(
            NodeCategory.IDENTITY, arn, {"name": "destroyer2", "principal_type": "role"}
        )
        # Then decorate with destructive_permissions.
        await writer.record_destructive_principals([arn])

        identities = await store.list_entities_by_type(
            tenant_id="tenant-dt2", entity_type=NodeCategory.IDENTITY.value
        )
        assert len(identities) == 1
        props = identities[0].properties
        # Both the original and new property must be present.
        assert props.get("destructive_permissions") is True
        assert props.get("principal_type") == "role"
