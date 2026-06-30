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

import hashlib


def secret_fingerprint(identifier: str) -> str:
    """Canonical convergence key for a credential whose plaintext id must NOT be stored.

    SECRET-node key for credentials where the natural identifier is not an approved-plaintext value
    (the only approved plaintext is the AWS access-key-id). Both the finder (appsec — a credential
    leaked in code) and the owner (identity — the cloud principal that holds it) hash the SAME
    non-secret identifier (e.g. a GCP service-account key's ``private_key_id``) through this function,
    so the two signals collapse onto one graph node with NOTHING readable stored. The hashed value is
    the key id, never the private key material. ``sha256`` hex, prefixed for node-key legibility.
    """
    return f"secretfp:{hashlib.sha256(identifier.encode()).hexdigest()}"


def s3_bucket_arn(bucket_name: str) -> str:
    """Canonical ARN for an S3 bucket: ``arn:aws:s3:::{bucket_name}``."""
    return f"arn:aws:s3:::{bucket_name}"


def azure_blob_uri(storage_account: str, container: str) -> str:
    """Canonical key for an Azure Blob container (multi-cloud spine, gap #13).

    Azure resources have no ARN; the blob-endpoint URL is the stable, globally-unique
    identifier — the Azure analogue of an S3 ARN.
    """
    return f"https://{storage_account}.blob.core.windows.net/{container}"


def gcs_uri(bucket_name: str) -> str:
    """Canonical key for a GCS bucket (multi-cloud spine, gap #13): ``gs://{bucket_name}``."""
    return f"gs://{bucket_name}"
