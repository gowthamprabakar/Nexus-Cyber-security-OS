"""D.4 v0.2 Task 16 — block action emission flow tests."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.actions.emission_flow import (
    BLOCK_REF_KEY,
    INVESTIGATION_KEY,
    attach_block_handoff,
    block_audit_entry,
    emit_block_for_finding,
    should_emit_block,
)

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def test_should_emit_block() -> None:
    assert should_emit_block("Critical") is True and should_emit_block("high") is True
    assert should_emit_block("medium") is False


def test_emit_block_for_critical_public_ip() -> None:
    block = emit_block_for_finding(
        severity="critical", target_ip="8.8.8.8", ttl_seconds=300, reason="C2", requested_at=_T
    )
    assert block is not None and block.target_ip == "8.8.8.8" and block.ttl_seconds == 300


def test_no_block_for_low_severity() -> None:
    assert (
        emit_block_for_finding(
            severity="low", target_ip="8.8.8.8", ttl_seconds=300, reason="r", requested_at=_T
        )
        is None
    )


def test_no_block_for_private_ip_safe_default() -> None:
    # The guard rejects private IPs; the flow returns None (no block) rather than raising.
    assert (
        emit_block_for_finding(
            severity="critical", target_ip="10.0.0.5", ttl_seconds=300, reason="r", requested_at=_T
        )
        is None
    )


def test_block_audit_entry_emitted() -> None:
    block = emit_block_for_finding(
        severity="high", target_ip="8.8.8.8", ttl_seconds=300, reason="r", requested_at=_T
    )
    assert block is not None
    entry = block_audit_entry(block, event="block_emitted")
    assert entry["event"] == "block_emitted" and entry["target_ip"] == "8.8.8.8"
    assert entry["ttl_seconds"] == 300 and entry["action_type"] == "temporary_ip_block"


def test_block_audit_entry_expired() -> None:
    block = emit_block_for_finding(
        severity="high", target_ip="8.8.8.8", ttl_seconds=300, reason="r", requested_at=_T
    )
    assert block is not None
    assert block_audit_entry(block, event="block_expired")["event"] == "block_expired"


def test_attach_handoff_sets_flag_and_block_ref() -> None:
    out = attach_block_handoff({"sig": "C2"}, recommended=True, block_ref="block-1")
    assert out[INVESTIGATION_KEY] is True and out[BLOCK_REF_KEY] == "block-1"
    assert out["sig"] == "C2"


def test_attach_handoff_without_block_ref() -> None:
    out = attach_block_handoff({}, recommended=False)
    assert out[INVESTIGATION_KEY] is False and BLOCK_REF_KEY not in out


def test_attach_does_not_mutate_input() -> None:
    ev: dict[str, object] = {}
    attach_block_handoff(ev, recommended=True)
    assert ev == {}


def test_no_auto_escalation_surface() -> None:
    # Q6: D.4 emits the flag only — no escalate/notify function.
    import network_threat.actions.emission_flow as mod

    assert not hasattr(mod, "escalate")
    assert not hasattr(mod, "notify_investigation")
