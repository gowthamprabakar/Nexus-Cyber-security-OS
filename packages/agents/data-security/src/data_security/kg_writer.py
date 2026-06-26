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


def _grants_s3_read(actions: Any) -> bool:
    """True if a policy statement grants an S3 read (``*`` / ``s3:*`` / ``s3:get*``)."""
    values = actions if isinstance(actions, list) else [actions]
    return any(
        isinstance(a, str) and (a.lower() in {"*", "s3:*"} or a.lower().startswith("s3:get"))
        for a in values
    )


def _specific_aws_principals(principal: Any) -> list[str]:
    """Non-wildcard ``Principal.AWS`` ARNs (a wildcard is public, handled separately)."""
    if not isinstance(principal, dict):
        return []
    aws = principal.get("AWS")
    values = [aws] if isinstance(aws, str) else list(aws or [])
    return [v for v in values if isinstance(v, str) and v != "*"]


def _policy_reader_principals(policy_json: str | None) -> list[str]:
    """Specific principal ARNs granted S3 read by the bucket policy (resource-based access).

    The mirror of :func:`_policy_grants_public` for *named* principals: a bucket policy can grant
    a specific IAM principal read access without any IAM-side policy, so identity's grant
    resolution can't see it. data-security records these on its own bucket node; the kg_query
    correlation layer joins them to sensitive data (gap #7). Deduped, order-preserving.
    """
    if not policy_json:
        return []
    try:
        statements = json.loads(policy_json).get("Statement") or []
    except (json.JSONDecodeError, AttributeError):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        if not _grants_s3_read(stmt.get("Action")):
            continue
        for arn in _specific_aws_principals(stmt.get("Principal")):
            if arn not in seen:
                seen.add(arn)
                out.append(arn)
    return out


def _bucket_is_public(bucket: BucketInventory) -> bool:
    """Whether the bucket is internet-public via ACL or bucket policy.

    ACL path: an AllUsers/AuthenticatedUsers grant. Policy path: a wildcard-principal
    ``Allow`` — but neutralized when Block-Public-Access blocks/restricts public policies.
    """
    if bucket.acl.grants_all_users or bucket.acl.grants_authenticated_users:
        return True
    # Defensive getattr: the real BucketInventory always carries these (pydantic defaults),
    # but a minimal test double may supply only `acl` → fall back to ACL-only.
    pab = getattr(bucket, "public_access_block", None)
    if pab is not None and (pab.restrict_public_buckets or pab.block_public_policy):
        return False
    return _policy_grants_public(getattr(bucket, "policy_json", None))


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
        *,
        public_object_buckets: set[str] | frozenset[str] | None = None,
    ) -> None:
        """Upsert each bucket's storage node + its detected data-classification nodes.

        ``public_object_buckets`` (gap #2) is the set of bucket names that have at least one
        object made public via its **object ACL**; those buckets are treated as exposing data
        even when the bucket itself is private.
        """
        public_object = public_object_buckets or frozenset()
        for bucket in buckets:
            public = _bucket_is_public(bucket) or bucket.name in public_object
            encrypted = bucket.encryption.algorithm != "NONE"
            storage_props: dict[str, Any] = {
                "resource_type": "s3-bucket",
                "region": bucket.region,
                "is_public": public,
                "is_encrypted": encrypted,
                "source": bucket.name,  # human-readable name as a property
            }
            # Resource-based access: principals granted S3 read by the bucket policy (gap #7).
            # Recorded on data-security's own node; the kg_query layer joins them to data.
            policy_readers = _policy_reader_principals(getattr(bucket, "policy_json", None))
            if policy_readers:
                storage_props["policy_readers"] = policy_readers
            storage_id = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                self._storage_external_id(bucket.name),
                storage_props,
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
