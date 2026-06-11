"""data-security v0.2 Task 11 — GDPR framework alignment tests (Q6)."""

from __future__ import annotations

from data_security.frameworks.gdpr import (
    GdprArticle,
    is_eu_region,
    map_gdpr,
)
from data_security.tools.data_source import DataCloud, DataSource


def _src(identifier: str, *, region: str = "eu-west-1", encrypted: bool = True) -> DataSource:
    return DataSource(
        cloud=DataCloud.AWS,
        identifier=identifier,
        region=region,
        is_public=False,
        is_encrypted=encrypted,
    )


def test_is_eu_region_multi_cloud() -> None:
    assert is_eu_region("eu-west-1") is True  # AWS
    assert is_eu_region("europe-west1") is True  # GCP
    assert is_eu_region("westeurope") is True  # Azure
    assert is_eu_region("us-east-1") is False


def test_sensitive_source_gets_art30_and_art17() -> None:
    findings = map_gdpr([_src("pii-bucket")], sensitive_identifiers={"pii-bucket"})
    articles = {f.article for f in findings}
    assert GdprArticle.ART_30 in articles and GdprArticle.ART_17 in articles


def test_unencrypted_sensitive_gets_art32() -> None:
    findings = map_gdpr([_src("pii", encrypted=False)], sensitive_identifiers={"pii"})
    [art32] = [f for f in findings if f.article == GdprArticle.ART_32]
    assert art32.severity == "high"


def test_encrypted_no_art32() -> None:
    findings = map_gdpr([_src("pii", encrypted=True)], sensitive_identifiers={"pii"})
    assert not any(f.article == GdprArticle.ART_32 for f in findings)


def test_eu_region_gets_art5() -> None:
    findings = map_gdpr([_src("pii", region="eu-central-1")], sensitive_identifiers={"pii"})
    assert any(f.article == GdprArticle.ART_5 for f in findings)


def test_non_eu_no_art5() -> None:
    findings = map_gdpr([_src("pii", region="us-east-1")], sensitive_identifiers={"pii"})
    assert not any(f.article == GdprArticle.ART_5 for f in findings)


def test_non_sensitive_source_skipped() -> None:
    assert map_gdpr([_src("clean")], sensitive_identifiers=set()) == ()


def test_findings_are_metadata_only() -> None:
    # Source identifier + article + severity + message — no content (WI-S10).
    [f, *_] = map_gdpr([_src("pii")], sensitive_identifiers={"pii"})
    assert f.source == "pii" and isinstance(f.message, str)
    assert set(type(f).__slots__) == {"article", "source", "severity", "message"}
