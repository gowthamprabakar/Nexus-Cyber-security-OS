"""audit v0.2 Task 4 — aggregation result normalization tests (Q1/WI-F5)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.aggregation.multi_chain_query import aggregate_chains
from audit.aggregation.normalize import normalize_aggregation
from audit.schemas import AuditEvent
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT = "01HV0T0000000000000000TENA"


def _chain(agent: str, actions: list[str], *, base_offset: int = 0) -> list[AuditEvent]:
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
                tenant_id=_TENANT,
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


def _report(chains: dict[str, list[AuditEvent]]):
    return normalize_aggregation(aggregate_chains(chains, tenant_id=_TENANT))


def test_records_are_ocsf_6003() -> None:
    report = _report({"cloud_posture": _chain("cloud_posture", ["scan"])})
    assert report.total == 1
    assert report.records[0]["class_uid"] == 6003


def test_chain_hashes_in_unmapped() -> None:
    # WI-F5: chain hashes ride in the unmapped slot, byte-identical.
    report = _report({"cloud_posture": _chain("cloud_posture", ["scan"])})
    unmapped = report.records[0]["unmapped"]
    assert "previous_hash" in unmapped and "entry_hash" in unmapped and "source" in unmapped


def test_provenance_preserved_per_entry() -> None:
    report = _report({"compliance": _chain("compliance", ["map"])})
    rec = report.records[0]
    assert rec["actor"]["user"]["name"] == "compliance"  # agent provenance
    assert rec["unmapped"]["source"].startswith("jsonl:")


def test_time_ordered_across_chains() -> None:
    report = _report(
        {
            "cloud_posture": _chain("cloud_posture", ["a"], base_offset=0),
            "compliance": _chain("compliance", ["b"], base_offset=5),
        }
    )
    times = [r["time"] for r in report.records]
    assert times == sorted(times)
    assert report.agents_covered() == ("cloud_posture", "compliance")


def test_broken_chains_carried() -> None:
    good = _chain("cloud_posture", ["a"])
    broken = _chain("compliance", ["x", "y"])
    broken[1] = broken[1].model_copy(update={"entry_hash": "0" * 64})
    report = _report({"cloud_posture": good, "compliance": broken})
    assert report.broken_chains == ("compliance",) and report.chains_verified == 2


def test_empty() -> None:
    report = _report({})
    assert report.total == 0 and report.records == () and report.agents_covered() == ()
