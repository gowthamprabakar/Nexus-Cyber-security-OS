"""Data-security knowledge-graph writer (v0.4 Stage 1.5/D.5).

Writes the data-classification inventory the catalogue (#711) assigns DSPM into the
fleet graph from the typed ``BucketInventory`` + classifier hits the agent already
produces: a **storage** node per bucket + a **DATA_CLASSIFICATION** node per detected
sensitive data-type, linked ``CONTAINS`` (and ``EXPOSES_DATA`` when the bucket is
public). Labels only — the classifier returns a `ClassifierLabel`, never the matched
substring (Q6 privacy contract), so no raw data crosses into the graph.

Storage nodes are catalogue-D.3-owned (`CLOUD_RESOURCE`); DSPM **contributes** the
classification + the CONTAINS edge (the catalogue ownership rule). Subclasses
:class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed vocabulary
(ADR-018), within-run dedup, opt-in/inert when no store. Offline default writes
nothing → artifacts byte-identical.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from data_security.canonical import s3_bucket_arn
from data_security.schemas import ClassifierLabel

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from data_security.tools.s3_inventory import BucketInventory


def _principal_is_wildcard(principal: Any) -> bool:
    """True when a statement Principal opens access to the whole internet (``*``)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


def _policy_grants_public(policy_json: str | None) -> bool:
    """True if a bucket policy has an ``Allow`` statement to a wildcard principal.

    A bucket policy with ``Principal: *`` is the dominant modern way an S3 bucket is made
    public (AWS disables ACLs by default). Malformed JSON is treated as non-public.
    """
    if not policy_json:
        return False
    try:
        statements = json.loads(policy_json).get("Statement") or []
    except (json.JSONDecodeError, AttributeError):
        return False
    return any(
        stmt.get("Effect") == "Allow" and _principal_is_wildcard(stmt.get("Principal"))
        for stmt in statements
        if isinstance(stmt, dict)
    )


def _bucket_is_public(bucket: BucketInventory) -> bool:
    """Whether the bucket is internet-public via ACL or bucket policy.

    ACL path: an AllUsers/AuthenticatedUsers grant. Policy path: a wildcard-principal
    ``Allow`` — but neutralized when Block-Public-Access blocks/restricts public policies.
    """
    if bucket.acl.grants_all_users or bucket.acl.grants_authenticated_users:
        return True
    pab = bucket.public_access_block
    if pab.restrict_public_buckets or pab.block_public_policy:
        return False
    return _policy_grants_public(bucket.policy_json)


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists storage + data-classification inventory for the fleet graph."""

    @staticmethod
    def _storage_external_id(bucket_name: str) -> str:
        """Canonical key for the CLOUD_RESOURCE spine node (ARN = fleet-graph join key)."""
        return s3_bucket_arn(bucket_name)

    async def record(
        self,
        buckets: Sequence[BucketInventory],
        classifier_hits_by_bucket: Mapping[str, Sequence[ClassifierLabel]],
    ) -> None:
        """Upsert each bucket's storage node + its detected data-classification nodes."""
        for bucket in buckets:
            public = _bucket_is_public(bucket)
            encrypted = bucket.encryption.algorithm != "NONE"
            storage_id = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                self._storage_external_id(bucket.name),
                {
                    "resource_type": "s3-bucket",
                    "region": bucket.region,
                    "is_public": public,
                    "is_encrypted": encrypted,
                    "source": bucket.name,  # human-readable name as a property
                },
            )
            seen: set[str] = set()
            for label in classifier_hits_by_bucket.get(bucket.name, ()):
                if label is ClassifierLabel.NONE or label.value in seen:
                    continue
                seen.add(label.value)
                classification_id = await self.upsert_node(
                    NodeCategory.DATA_CLASSIFICATION,
                    f"{bucket.name}:{label.value}",
                    {"data_type": label.value, "source": bucket.name},
                )
                await self.add_edge(storage_id or "", classification_id or "", EdgeType.CONTAINS)
                if public:
                    await self.add_edge(
                        storage_id or "", classification_id or "", EdgeType.EXPOSES_DATA
                    )


__all__ = ["KnowledgeGraphWriter"]
