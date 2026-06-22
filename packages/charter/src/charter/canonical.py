"""Canonical cross-agent resource identifiers — the fleet-graph join key (ADR-023).

Single source of truth: every agent keys its CLOUD_RESOURCE node by the canonical
cloud ARN built here, so independent signals about the same real resource collapse
onto ONE graph node (SemanticStore.upsert_entity is idempotent on
``(tenant, type, external_id)``). See ADR-023 for the convention and the deferred
bridge-edge plan for the misfit agents (vulnerability=image-ref, network=IP).

Add a builder here when a new resource type joins the spine — do not re-derive ARNs
in agent code.
"""

from __future__ import annotations


def s3_bucket_arn(bucket_name: str) -> str:
    """Canonical ARN for an S3 bucket: ``arn:aws:s3:::{bucket_name}``.

    # ponytail: S3-only. Other resource ARNs aren't name-derivable — add a
    # per-service builder here when a second resource type joins the spine.
    """
    return f"arn:aws:s3:::{bucket_name}"
