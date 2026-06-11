"""audit v0.2 Task 3 — cross-agent chain query aggregator tests (Q1/Q6/WI-F2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.aggregation.multi_chain_query import aggregate_chains
from audit.schemas import AuditEvent
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


def _chain(
    agent: str, actions: list[str], *, tenant: str = _TENANT_A, base_offset: int = 0
) -> list[AuditEvent]:
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i, action in enumerate(actions):
        emitted_at = base + timedelta(seconds=base_offset + i)
        ts = emitted_at.isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=ts,
            agent=agent,
            run_id=f"{agent}-{i:03d}",
            action=action,
            payload=payload,
            previous_hash=previous_hash,
        )
        events.append(
            AuditEvent(
                tenant_id=tenant,
                correlation_id=f"{agent}-{i:03d}",
                agent_id=agent,
                action=action,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                emitted_at=emitted_at,
                source=f"jsonl:/tmp/{agent}.jsonl",
            )
        )
        previous_hash = entry_hash
    return events


def test_aggregate_single_chain() -> None:
    result = aggregate_chains(
        {"cloud_posture": _chain("cloud_posture", ["scan", "emit"])}, tenant_id=_TENANT_A
    )
    assert len(result.events) == 2 and result.chains_verified == 1 and result.broken_chains == ()


def test_aggregate_multiple_chains_time_ordered() -> None:
    chains = {
        "cloud_posture": _chain("cloud_posture", ["a"], base_offset=0),
        "compliance": _chain("compliance", ["b"], base_offset=10),
    }
    result = aggregate_chains(chains, tenant_id=_TENANT_A)
    assert [e.action for e in result.events] == ["a", "b"]  # time-ordered across chains


def test_tenant_isolation_excludes_other_tenant() -> None:
    chains = {
        "cloud_posture": _chain("cloud_posture", ["a"], tenant=_TENANT_A),
        "compliance": _chain("compliance", ["b"], tenant=_TENANT_B),
    }
    result = aggregate_chains(chains, tenant_id=_TENANT_A)
    assert [e.action for e in result.events] == ["a"]  # tenant B excluded (Q6)


def test_broken_chain_flagged_and_excluded() -> None:
    good = _chain("cloud_posture", ["a", "b"])
    broken = _chain("compliance", ["x", "y"])
    # Tamper: replace the 2nd event's entry_hash -> chain breaks.
    broken[1] = broken[1].model_copy(update={"entry_hash": "0" * 64})
    result = aggregate_chains({"cloud_posture": good, "compliance": broken}, tenant_id=_TENANT_A)
    assert result.broken_chains == ("compliance",)  # WI-F2: flagged, not repaired
    assert all(e.agent_id == "cloud_posture" for e in result.events)  # broken chain excluded


def test_verify_false_skips_verification() -> None:
    result = aggregate_chains(
        {"cloud_posture": _chain("cloud_posture", ["a"])}, tenant_id=_TENANT_A, verify=False
    )
    assert result.chains_verified == 0 and len(result.events) == 1


def test_empty() -> None:
    result = aggregate_chains({}, tenant_id=_TENANT_A)
    assert result.events == () and result.broken_chains == ()


def test_never_repairs_broken_chain() -> None:
    # The aggregator has no repair/mutate surface (WI-F2 architectural invariant).
    import audit.aggregation.multi_chain_query as mod

    assert not hasattr(mod, "repair") and not hasattr(mod, "fix_chain")
