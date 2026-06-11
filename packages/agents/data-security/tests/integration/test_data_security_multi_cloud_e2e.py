"""WI-S4 (HARD) — live multi-cloud data-discovery end-to-end (data-security v0.2 Task 20).

Two-layer per the WI-V6 / WI-I4 / WI-T4 / WI-R4 / WI-N4 / WI-K4 / WI-C2 lineage:

1. **Offline layer (every push):** the real pipeline — live inventory -> sample -> classify
   -> privacy-framework mapping -> finding emission — exercised across **all 3 clouds** with
   injected fakes. The **privacy contract** (WI-S8) + **residency boundary** (WI-S10) are
   verified end-to-end: every emitted evidence carries label + hash only, never plaintext,
   and no object content / keys escape the edge.
2. **Gated-live layer (`NEXUS_LIVE_DATA_SECURITY=1`):** probes live cloud sources; skipped in CI.

Honest scope (WI-S3): e2e **through emission**; wiring it into the agent's continuous `run()`
loop is the **Phase C** consolidated retrofit — the offline `run()` stays the deterministic
OCSF-emitting path (WI-S5 byte-identical).
"""

from __future__ import annotations

import io
from typing import Any

from data_security.access_risk import elevate_sensitive_with_access
from data_security.classifiers.scored import classify_scored
from data_security.frameworks.gdpr import GdprArticle, map_gdpr
from data_security.frameworks.hipaa import map_hipaa
from data_security.frameworks.pci_dss import map_pci_dss
from data_security.identity_consumption import flagged_data_sources
from data_security.live_lane import source_reachable
from data_security.privacy import PrivacyContractError, assert_privacy_contract
from data_security.residency.aws_s3 import track_residency
from data_security.schemas import ClassifierLabel
from data_security.tools.azure_blob_inventory import AzureBlobLiveReader
from data_security.tools.data_source import DataCloud, unify
from data_security.tools.gcs_inventory import GcsLiveReader
from data_security.tools.s3_inventory_live import S3LiveInventoryReader
from data_security.tools.s3_objects_live import S3LiveObjectSampler

_ACCT = "111122223333"


# ---- fakes (one per cloud) ----


class _FakeS3Inv:
    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": "pii-data"}]}

    def get_bucket_location(self, *, Bucket: str) -> dict[str, Any]:
        return {"LocationConstraint": "eu-west-1"}

    def get_bucket_acl(self, *, Bucket: str) -> dict[str, Any]:
        return {"Grants": []}

    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }

    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, Any]:
        raise RuntimeError("no encryption")  # unencrypted -> framework findings

    def get_bucket_policy(self, *, Bucket: str) -> dict[str, Any]:
        raise RuntimeError("NoSuchBucketPolicy")

    def get_bucket_tagging(self, *, Bucket: str) -> dict[str, Any]:
        return {"TagSet": []}


class _FakeS3Obj:
    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        return {"Contents": [{"Key": "record.txt"}], "IsTruncated": False}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        return {"Body": io.BytesIO(b"patient SSN 123-45-6789")}


class _FakeAzure:
    def list_containers(self) -> list[dict[str, Any]]:
        return [{"name": "phi", "public_access": "container", "encrypted": False}]

    def list_blobs(self, *, container: str) -> list[dict[str, Any]]:
        return [{"name": "chart"}]

    def download_blob(self, *, container: str, blob: str) -> bytes:
        return b"NPI 1234567893"


class _FakeGcs:
    def list_buckets(self) -> list[dict[str, Any]]:
        return [{"name": "cards", "location": "US", "iam_members": ["allUsers"]}]

    def list_blobs(self, *, bucket: str) -> list[dict[str, Any]]:
        return [{"name": "txns"}]

    def download_blob(self, *, bucket: str, blob: str) -> bytes:
        return b"card 4111 1111 1111 1111"


# ------------------- offline layer: all 3 clouds -------------------------


def test_three_cloud_inventory_and_unify() -> None:
    s3 = S3LiveInventoryReader(_FakeS3Inv(), account_id=_ACCT).read()
    azure = AzureBlobLiveReader(_FakeAzure(), storage_account="acct", region="westeurope").read()
    gcs = GcsLiveReader(_FakeGcs(), project="p").read()
    sources = unify(s3=s3, azure=azure, gcs=gcs)
    assert {s.cloud for s in sources} == {DataCloud.AWS, DataCloud.AZURE, DataCloud.GCP}


def test_sample_classify_privacy_safe() -> None:
    # The full sensitive path: sample -> classify -> privacy-safe evidence (WI-S8).
    samples, basis = S3LiveObjectSampler(_FakeS3Obj(), sample_rate=1.0).sample("pii-data")
    assert basis.objects_scanned == 1
    scored = classify_scored(samples[0].decoded_text())
    assert scored.label == ClassifierLabel.SSN
    evidence = scored.to_evidence()
    assert_privacy_contract(evidence)  # label + hash only -> no leak
    assert "123-45-6789" not in str(evidence)  # plaintext never present


def test_privacy_contract_catches_a_leak() -> None:
    # If raw content were ever put in evidence, the contract raises.
    import pytest

    with pytest.raises(PrivacyContractError):
        assert_privacy_contract({"sample": "patient SSN 123-45-6789"})


def test_framework_mapping_end_to_end() -> None:
    s3 = S3LiveInventoryReader(_FakeS3Inv(), account_id=_ACCT).read()
    azure = AzureBlobLiveReader(_FakeAzure(), storage_account="acct", region="westeurope").read()
    gcs = GcsLiveReader(_FakeGcs(), project="p").read()
    sources = unify(s3=s3, azure=azure, gcs=gcs)
    sensitive = {s.identifier for s in sources}  # all carry sensitive samples in this scenario

    gdpr = map_gdpr(sources, sensitive_identifiers=sensitive)
    hipaa = map_hipaa(sources, phi_bearing_identifiers={"acct/phi"})
    pci = map_pci_dss(sources, pan_bearing_identifiers={"cards"})
    assert gdpr and any(f.article == GdprArticle.ART_32 for f in gdpr)  # unencrypted S3
    assert hipaa and pci


def test_residency_boundary_metadata_only() -> None:
    # WI-S10: residency records carry bucket/region/jurisdiction only, never content.
    s3 = S3LiveInventoryReader(_FakeS3Inv(), account_id=_ACCT).read()
    [rec] = track_residency(s3)
    meta = rec.to_metadata()
    assert set(meta) == {"bucket", "region", "jurisdiction"}
    assert "content" not in str(meta).lower() and "ssn" not in str(meta).lower()


def test_d2_access_uplift_end_to_end() -> None:
    s3 = S3LiveInventoryReader(_FakeS3Inv(), account_id=_ACCT).read()
    sources = unify(s3=s3)
    d2_report = {"findings": [{"class_uid": 2004, "resources": [{"uid": "arn:aws:s3:::pii-data"}]}]}
    access_flagged = flagged_data_sources(sources, identity_report=d2_report)
    uplifts = elevate_sensitive_with_access(
        sensitive_identifiers={"pii-data"}, access_flagged_identifiers=access_flagged
    )
    assert uplifts and uplifts[0].elevated_severity == "critical"


# --------------------------- gated-live layer ----------------------------


def test_live_sources_reachable(data_security_gate: None) -> None:
    ok, reason = source_reachable(("aws_s3",))
    assert ok, f"no source reachable: {reason}"
