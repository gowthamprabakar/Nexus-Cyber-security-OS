"""WI-F4 (HARD) — live cross-agent audit end-to-end (audit v0.2 Task 16).

Two-layer per the WI-V6 / WI-I4 / WI-T4 / WI-R4 / WI-N4 / WI-K4 / WI-C2 / WI-S4 lineage:

1. **Offline layer (every push):** the real F.6 pipeline across several agents' chains —
   enumerate -> aggregate (verify + tenant-isolate) -> normalize to OCSF 6003 -> Merkle index
   -> tamper detect + alert -> typed query -> compliance evidence proof + verify. The
   **read-only invariant** (WI-F8) and **cross-tenant admin gate** (WI-F11) are exercised, and
   a **tamper injection** confirms an alert always surfaces (WI-F9).
2. **Gated-live layer (`NEXUS_LIVE_AUDIT=1`):** probes live audit sources; skipped in CI.

Honest scope (WI-F3): e2e **through emission**; wiring it into the agent's continuous `run()`
loop is the **Phase C** consolidated retrofit — the offline `run()` stays the deterministic
OCSF-6003-emitting path (WI-F5 byte-identical). No tests/integration/__init__.py (importlib).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from audit.aggregation.agent_enumerator import enumerate_chains
from audit.aggregation.multi_chain_query import aggregate_chains
from audit.aggregation.normalize import normalize_aggregation
from audit.compliance_integration.evidence_chain import (
    attach_proofs_to_evidence,
    build_evidence_proofs,
)
from audit.compliance_integration.verify_api import verify_evidence_proofs
from audit.live_lane import source_reachable
from audit.merkle.tree import build_merkle_tree
from audit.query.engine import apply_filter
from audit.query.typed_filter import TypedAuditFilter
from audit.readonly import UnauthorizedAuditMutationError, assert_audit_readonly
from audit.schemas import AuditEvent
from audit.tamper.alert import emit_tamper_alerts
from audit.tamper.detect import detect_tampering
from audit.tenant_authz import (
    CrossTenantAuditAuthorizationError,
    assert_admin_for_cross_tenant,
    cross_tenant_query,
)
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT = "01HV0T0000000000000000TENA"


def _chain(agent: str, actions: list[str], *, base_offset: int = 0) -> list[AuditEvent]:
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i, action in enumerate(actions):
        emitted_at = base + timedelta(seconds=base_offset + i)
        ts = emitted_at.isoformat().replace("+00:00", "Z")
        payload = {"i": i, "status": "success"}
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


def _fleet() -> dict[str, list[AuditEvent]]:
    return {
        "cloud_posture": _chain("cloud_posture", ["scan", "emit"], base_offset=0),
        "compliance": _chain("compliance", ["evaluate", "emit"], base_offset=10),
        "data_security": _chain("data_security", ["classify"], base_offset=20),
    }


# ------------------------- offline layer --------------------------------


def test_enumerate_then_aggregate_to_ocsf_6003() -> None:
    sources = enumerate_chains(agent_chains={a: f"/data/{a}.jsonl" for a in _fleet()})
    assert len(sources) == 3
    report = normalize_aggregation(aggregate_chains(_fleet(), tenant_id=_TENANT))
    assert report.total == 5
    assert all(r["class_uid"] == 6003 for r in report.records)
    assert report.agents_covered() == ("cloud_posture", "compliance", "data_security")


def test_merkle_index_over_aggregated_chain() -> None:
    events = aggregate_chains(_fleet(), tenant_id=_TENANT).events
    tree = build_merkle_tree([e.entry_hash for e in events])
    assert len(tree.root) == 64


def test_tamper_injection_always_alerts() -> None:
    # WI-F9: inject a tamper -> an alert ALWAYS surfaces.
    chain = _chain("compliance", ["a", "b", "c"])
    chain[1] = chain[1].model_copy(update={"action": "FORGED"})
    assert detect_tampering(chain)  # detected
    alerts = emit_tamper_alerts("compliance-chain", chain)
    assert alerts and alerts[0]["class_uid"] == 6003


def test_typed_query_over_aggregate() -> None:
    events = aggregate_chains(_fleet(), tenant_id=_TENANT).events
    out = apply_filter(events, TypedAuditFilter(tenant_id=_TENANT, agent_id="compliance"))
    assert {e.agent_id for e in out} == {"compliance"}


def test_compliance_evidence_proof_end_to_end() -> None:
    events = _chain("compliance", ["evaluate", "emit"])
    proofs = build_evidence_proofs(events, ["compliance-000"])
    evidence = attach_proofs_to_evidence({"control_id": "CIS-1.1"}, proofs)
    assert verify_evidence_proofs(evidence).all_valid is True


def test_readonly_invariant_exercised() -> None:
    # WI-F8: read ops pass; a mutation attempt is hard-blocked.
    assert_audit_readonly("aggregate")
    assert_audit_readonly("emit_finding")
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly("rewrite_chain")


def test_cross_tenant_admin_gate_exercised() -> None:
    # WI-F11: cross-tenant needs admin; a viewer is blocked.
    q = cross_tenant_query(all_tenants=True)
    assert_admin_for_cross_tenant(q, "admin")
    with pytest.raises(CrossTenantAuditAuthorizationError):
        assert_admin_for_cross_tenant(q, "viewer")


# --------------------------- gated-live layer ----------------------------


def test_live_sources_reachable(audit_gate: None) -> None:
    ok, reason = source_reachable(("f5_episodes",))
    assert ok, f"no audit source reachable: {reason}"
