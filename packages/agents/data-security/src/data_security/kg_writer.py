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

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from data_security.schemas import ClassifierLabel

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from data_security.tools.s3_inventory import BucketInventory


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists storage + data-classification inventory for the fleet graph."""

    async def record(
        self,
        buckets: Sequence[BucketInventory],
        classifier_hits_by_bucket: Mapping[str, Sequence[ClassifierLabel]],
    ) -> None:
        """Upsert each bucket's storage node + its detected data-classification nodes."""
        for bucket in buckets:
            public = bool(bucket.acl.grants_all_users or bucket.acl.grants_authenticated_users)
            encrypted = bucket.encryption.algorithm != "NONE"
            storage_id = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                bucket.name,
                {
                    "resource_type": "s3-bucket",
                    "region": bucket.region,
                    "is_public": public,
                    "is_encrypted": encrypted,
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
