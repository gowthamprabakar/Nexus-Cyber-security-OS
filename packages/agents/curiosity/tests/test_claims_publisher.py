"""Tests — `curiosity.claims_publisher` (Task 9).

The first DAY-12-specific live use of ADR-012's claims.> substrate.
Mocks JetStreamClient — no live NATS.

13 tests covering:

1. js_client=None -> no-op + log (Q5 default).
2. Single claim publish: js_client.publish called with the right
   stream + subject + payload.
3. Subject is `claims.tenant.<customer_id>.agent.curiosity`.
4. Stream is CLAIMS_STREAM.
5. Payload is JSON bytes round-trippable to the same claim.
6. Batch publish: no-op + log when js_client=None.
7. Batch publish: no-op + log when claims=[].
8. Batch publish returns the count.
9. Mixed-customer batch — each claim uses its OWN customer_id
   for the subject. v0.1 driver builds single-customer batches
   but the publisher is mixed-batch-safe.
10. Provider exception propagates (driver decides retry vs abort).
11. publish_claims yields zero when js_client=None even with claims present.
12. Multiple claims publish in order (FIFO).
13. claims.> subject does NOT collide with findings.> shape
    (regression: ensures claims_subject builder is wired, not
    findings_subject).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from curiosity.claims_publisher import publish_claim, publish_claims
from curiosity.schemas import (
    CoverageGap,
    CuriosityClaim,
    Hypothesis,
    ProbeAction,
    ProbeDirective,
    TargetAgent,
)
from shared.fabric import CLAIMS_STREAM, JetStreamClient

_VALID_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
_OTHER_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHG0"


def _make_js_client() -> JetStreamClient:
    client = AsyncMock(spec=JetStreamClient)
    client.publish = AsyncMock(return_value=MagicMock(stream="claims", seq=1))
    return cast(JetStreamClient, client)


def _gap() -> CoverageGap:
    return CoverageGap(
        region="us-east-1",
        asset_count=42,
        days_since_last_finding=60,
        severity_hint="medium",
    )


def _directive() -> ProbeDirective:
    return ProbeDirective(
        target_agent=TargetAgent.DATA_SECURITY,
        target_resource_arn="arn:aws:s3:::region-bucket",
        action=ProbeAction.SCAN,
        rationale_ref=_VALID_ULID,
    )


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        statement="Region us-east-1 appears under-scanned.",
        rationale=(
            "Region us-east-1 has 42 assets but no findings in 60 days. "
            "Consistent with either clean posture or a coverage gap. "
            "Recommend running D.5 to establish a baseline."
        ),
        probe_directive=_directive(),
        cited_gap=_gap(),
    )


def _claim(**overrides: Any) -> CuriosityClaim:
    defaults: dict[str, Any] = {
        "claim_id": _VALID_ULID,
        "customer_id": "acme",
        "hypothesis": _hypothesis(),
        "emitted_at": datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return CuriosityClaim(**defaults)


# ---------------------------------------------------------------------------
# Single-claim publish
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_claim_no_op_when_client_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="curiosity.claims_publisher"):
        await publish_claim(None, _claim())
    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_publish_claim_calls_js_client_publish() -> None:
    client = _make_js_client()
    await publish_claim(client, _claim())
    client.publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_publish_claim_uses_correct_subject() -> None:
    client = _make_js_client()
    await publish_claim(client, _claim(customer_id="contoso"))
    call = client.publish.await_args
    # Positional args: (stream, subject, payload)
    subject = call.args[1]
    assert subject == "claims.tenant.contoso.agent.curiosity"


@pytest.mark.asyncio
async def test_publish_claim_uses_claims_stream() -> None:
    client = _make_js_client()
    await publish_claim(client, _claim())
    call = client.publish.await_args
    stream = call.args[0]
    assert stream is CLAIMS_STREAM


@pytest.mark.asyncio
async def test_publish_claim_payload_is_round_trippable_json() -> None:
    client = _make_js_client()
    claim = _claim()
    await publish_claim(client, claim)
    payload_bytes = client.publish.await_args.args[2]
    assert isinstance(payload_bytes, bytes)
    decoded = json.loads(payload_bytes.decode("utf-8"))
    # claim_id is the most stable round-trip key
    assert decoded["claim_id"] == claim.claim_id
    assert decoded["customer_id"] == "acme"
    assert decoded["agent_id"] == "curiosity"


@pytest.mark.asyncio
async def test_publish_claim_exception_propagates() -> None:
    """The driver decides retry vs abort; the publisher doesn't swallow."""
    client = AsyncMock(spec=JetStreamClient)
    client.publish = AsyncMock(side_effect=RuntimeError("simulated NATS failure"))
    with pytest.raises(RuntimeError, match="simulated NATS failure"):
        await publish_claim(cast(JetStreamClient, client), _claim())


# ---------------------------------------------------------------------------
# Batch publish
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_claims_no_op_when_client_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="curiosity.claims_publisher"):
        count = await publish_claims(js_client=None, claims=[_claim()])
    assert count == 0
    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_publish_claims_no_op_when_claims_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = _make_js_client()
    with caplog.at_level(logging.INFO, logger="curiosity.claims_publisher"):
        count = await publish_claims(js_client=client, claims=[])
    assert count == 0
    assert any("no claims" in rec.message for rec in caplog.records)
    client.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_publish_claims_returns_count() -> None:
    client = _make_js_client()
    claims = [_claim(), _claim(claim_id=_OTHER_ULID)]
    count = await publish_claims(js_client=client, claims=claims)
    assert count == 2
    assert client.publish.await_count == 2


@pytest.mark.asyncio
async def test_publish_claims_preserves_per_claim_customer_id() -> None:
    """Each claim's subject uses ITS OWN customer_id. Mixed-customer
    batches are supported at the publisher layer (driver typically
    builds single-customer batches; this is defence-in-depth)."""
    client = _make_js_client()
    claims = [
        _claim(claim_id=_VALID_ULID, customer_id="acme"),
        _claim(claim_id=_OTHER_ULID, customer_id="contoso"),
    ]
    await publish_claims(js_client=client, claims=claims)

    subjects = [call.args[1] for call in client.publish.await_args_list]
    assert "claims.tenant.acme.agent.curiosity" in subjects
    assert "claims.tenant.contoso.agent.curiosity" in subjects


@pytest.mark.asyncio
async def test_publish_claims_preserves_order() -> None:
    """Claims publish in input order."""
    client = _make_js_client()
    claims = [
        _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ"),
        _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG0"),
        _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG1"),
    ]
    await publish_claims(js_client=client, claims=claims)

    published_ids = []
    for call in client.publish.await_args_list:
        payload = json.loads(call.args[2].decode("utf-8"))
        published_ids.append(payload["claim_id"])
    assert published_ids == [
        "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        "01J7M3X9Z1K8RPVQNH2T8DBHG0",
        "01J7M3X9Z1K8RPVQNH2T8DBHG1",
    ]


# ---------------------------------------------------------------------------
# Subject-builder regression — claims.> not findings.>
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subject_uses_claims_root_not_findings() -> None:
    """Regression probe: ensure the publisher uses claims_subject, not
    findings_subject. The two builders take different argument
    counts so the wrong wire would explode loudly — this test
    asserts the right wire."""
    client = _make_js_client()
    await publish_claim(client, _claim(customer_id="acme"))
    subject = client.publish.await_args.args[1]
    assert subject.startswith("claims.tenant.")
    assert "agent.curiosity" in subject
    assert "findings" not in subject  # never the wrong stream
