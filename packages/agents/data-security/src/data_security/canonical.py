"""Canonical cross-agent resource identifiers (the fleet-graph join key)."""

from __future__ import annotations


def s3_bucket_arn(bucket_name: str) -> str:
    """The ARN cloud-posture/identity key their CLOUD_RESOURCE spine node by.

    Using it as data-security's storage-node external_id collapses the bucket
    to ONE graph node across agents (upsert_entity is idempotent on
    (tenant, type, external_id)).

    # ponytail: S3-only. Other resource ARNs aren't name-derivable — add a
    # per-service canonicalizer when a second resource type joins the spine.
    """
    return f"arn:aws:s3:::{bucket_name}"


__all__ = ["s3_bucket_arn"]
