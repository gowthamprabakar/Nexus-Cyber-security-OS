"""Stage 6 PUBLISH — fabric publish of CuriosityClaims to ``claims.>``.

D.12 is the **first publisher on the ``claims.>`` substrate**
introduced by ADR-012. This module wraps ``JetStreamClient``'s
``publish()`` method for the curiosity-specific use case:

- Subject construction via ``shared.fabric.claims_subject(tenant_id,
  agent_id="curiosity")`` — ``claims.tenant.<tid>.agent.curiosity``.
- Stream: ``shared.fabric.CLAIMS_STREAM`` — the 6th bus shipped in
  ADR-012's amendment.
- Payload: the ``CuriosityClaim`` model serialised as JSON via
  ``model_dump_json``. The wire format is the lightweight
  ``nexus_claim`` envelope (NOT OCSF) per the ADR's wire-format
  resolution.

**Single-tenant ``js_client=None`` opt-in default.** Per Q5, the
v0.1 driver default is ``js_client=None``, in which case the
publisher is a no-op-with-log. Production wires a real
``JetStreamClient`` (constructed with ``agent_id="curiosity"`` so
the subscriber-ACL fence ADR-012 ships still gates D.12 vs. A.1
the right way).

**Correlation_id.** The publish call resolves the correlation_id
from the ambient contextvar (``shared.fabric.correlation.
correlation_scope()``) that the agent driver (Task 10) sets at the
top of every run. Direct callers of this module must set their own
scope or pass ``correlation_id`` explicitly — the underlying
``JetStreamClient.publish`` raises ``MissingCorrelationIdError``
when both are absent.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from shared.fabric import CLAIMS_STREAM, JetStreamClient, claims_subject

from curiosity.schemas import CuriosityClaim

_LOG = logging.getLogger(__name__)


async def publish_claim(
    js_client: JetStreamClient | None,
    claim: CuriosityClaim,
) -> None:
    """Publish a single CuriosityClaim on ``claims.>``.

    Subject: ``claims.tenant.<customer_id>.agent.curiosity``.
    Payload: ``claim.model_dump_json()`` bytes.

    No-op-with-log when ``js_client`` is None (Q5 default). Direct
    callers of this module MUST be inside a ``correlation_scope``
    or have set ``correlation_id`` upstream — the substrate
    refuses messages without one.
    """
    if js_client is None:
        _LOG.info(
            "claims_publisher.publish_claim skipped: js_client=None "
            "(v0.1 single-tenant default); would have published claim %s",
            claim.claim_id,
        )
        return

    subject = claims_subject(claim.customer_id, claim.agent_id)
    payload = claim.model_dump_json().encode("utf-8")
    await js_client.publish(CLAIMS_STREAM, subject, payload)


async def publish_claims(
    *,
    js_client: JetStreamClient | None,
    claims: Sequence[CuriosityClaim],
) -> int:
    """Batch publish; returns the count successfully published.

    No-op-with-log when ``js_client`` is None or ``claims`` is
    empty. Otherwise iterates the claims and publishes each. Any
    publish-side exception from ``JetStreamClient`` propagates
    out of this call — the driver (Task 10) decides whether to
    retry or abort.

    Each claim's subject is derived from ITS OWN customer_id, so
    mixed-customer batches are supported at this layer. The
    driver typically builds single-customer batches because Q5
    forbids cross-tenant analysis upstream.
    """
    if not claims:
        _LOG.info("claims_publisher.publish_claims: no claims to publish")
        return 0

    if js_client is None:
        _LOG.info(
            "claims_publisher.publish_claims skipped: js_client=None "
            "(v0.1 single-tenant default); would have published %d claims",
            len(claims),
        )
        return 0

    count = 0
    for claim in claims:
        await publish_claim(js_client, claim)
        count += 1
    return count


__all__ = [
    "publish_claim",
    "publish_claims",
]
