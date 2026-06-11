"""data-security v0.2 Task 14 — D.2 Identity OCSF 2004 consumption tests (Q5)."""

from __future__ import annotations

from data_security.identity_consumption import (
    extract_flagged_resources,
    flagged_data_sources,
)
from data_security.tools.data_source import DataCloud, DataSource


def _d2_report(*arns: str) -> dict:
    return {
        "agent": "identity",
        "findings": [{"class_uid": 2004, "resources": [{"uid": a}]} for a in arns],
    }


def _src(identifier: str) -> DataSource:
    return DataSource(
        cloud=DataCloud.AWS,
        identifier=identifier,
        region="us-east-1",
        is_public=False,
        is_encrypted=True,
    )


def test_extract_flagged_resources() -> None:
    report = _d2_report("arn:aws:s3:::pii-data", "arn:aws:iam::1:role/admin")
    assert extract_flagged_resources(report) == {
        "arn:aws:s3:::pii-data",
        "arn:aws:iam::1:role/admin",
    }


def test_extract_ignores_non_2004() -> None:
    report = {"findings": [{"class_uid": 2003, "resources": [{"uid": "x"}]}]}
    assert extract_flagged_resources(report) == set()


def test_flagged_data_source_matched_by_arn() -> None:
    sources = [_src("pii-data"), _src("clean-bucket")]
    report = _d2_report("arn:aws:s3:::pii-data")
    assert flagged_data_sources(sources, identity_report=report) == {"pii-data"}


def test_no_match_when_absent() -> None:
    sources = [_src("clean-bucket")]
    report = _d2_report("arn:aws:s3:::other-bucket")
    assert flagged_data_sources(sources, identity_report=report) == set()


def test_name_field_also_extracted() -> None:
    report = {"findings": [{"class_uid": 2004, "resources": [{"name": "my-bucket"}]}]}
    assert flagged_data_sources([_src("my-bucket")], identity_report=report) == {"my-bucket"}


def test_empty_report() -> None:
    assert flagged_data_sources([_src("x")], identity_report={}) == set()
    assert extract_flagged_resources({}) == set()
