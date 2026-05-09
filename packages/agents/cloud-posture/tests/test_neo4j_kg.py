"""Tests for the Neo4j knowledge-graph writer (mocked async driver)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter


def _make_driver() -> tuple[MagicMock, MagicMock]:
    """Return (driver_mock, session_mock) wired as an async context manager.

    Layout: `async with driver.session() as session:` →
        session.run is an AsyncMock.
    """
    session = MagicMock()
    session.run = AsyncMock()

    driver = MagicMock()
    driver.session.return_value.__aenter__ = AsyncMock(return_value=session)
    driver.session.return_value.__aexit__ = AsyncMock(return_value=None)
    return driver, session


@pytest.mark.asyncio
async def test_upsert_asset_runs_merge_query() -> None:
    driver, session = _make_driver()
    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")

    await writer.upsert_asset(
        kind="aws_s3_bucket",
        external_id="arn:aws:s3:::alpha",
        properties={"region": "us-east-1", "name": "alpha"},
    )

    session.run.assert_awaited_once()
    cypher = session.run.call_args.args[0]
    kwargs = session.run.call_args.kwargs
    assert "MERGE" in cypher
    assert kwargs["customer_id"] == "cust_test"
    assert kwargs["kind"] == "aws_s3_bucket"
    assert kwargs["external_id"] == "arn:aws:s3:::alpha"
    assert kwargs["properties"] == {"region": "us-east-1", "name": "alpha"}


@pytest.mark.asyncio
async def test_upsert_asset_scopes_by_customer_id() -> None:
    """Cypher must constrain the MERGE by customer_id, not just kind/id."""
    driver, session = _make_driver()
    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")

    await writer.upsert_asset(kind="aws_iam_user", external_id="alice", properties={})

    cypher = session.run.call_args.args[0]
    assert "customer_id: $customer_id" in cypher


@pytest.mark.asyncio
async def test_upsert_finding_runs_two_queries_and_relates_assets() -> None:
    driver, session = _make_driver()
    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha"],
    )

    # Two queries: MERGE Finding, then MATCH/MERGE relationship per asset.
    assert session.run.await_count == 2

    finding_cypher = session.run.call_args_list[0].args[0]
    relate_cypher = session.run.call_args_list[1].args[0]
    assert "MERGE (f:Finding" in finding_cypher
    assert "AFFECTS" in relate_cypher
    assert "UNWIND" in relate_cypher


@pytest.mark.asyncio
async def test_upsert_finding_passes_severity_and_arns() -> None:
    driver, session = _make_driver()
    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-IAM-002-alice",
        rule_id="CSPM-AWS-IAM-002",
        severity="critical",
        affected_arns=[
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:iam::123456789012:user/bob",
        ],
    )

    finding_kwargs = session.run.call_args_list[0].kwargs
    relate_kwargs = session.run.call_args_list[1].kwargs
    assert finding_kwargs["severity"] == "critical"
    assert finding_kwargs["finding_id"] == "CSPM-AWS-IAM-002-alice"
    assert relate_kwargs["arns"] == [
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:iam::123456789012:user/bob",
    ]


@pytest.mark.asyncio
async def test_upsert_finding_with_no_affected_arns_skips_relation_query() -> None:
    """A finding with empty affected_arns should not run the relate query."""
    driver, session = _make_driver()
    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")

    await writer.upsert_finding(
        finding_id="CSPM-AWS-ORG-001-x",
        rule_id="CSPM-AWS-ORG-001",
        severity="medium",
        affected_arns=[],
    )

    # Only the Finding MERGE; no relation query when there's nothing to relate.
    assert session.run.await_count == 1
