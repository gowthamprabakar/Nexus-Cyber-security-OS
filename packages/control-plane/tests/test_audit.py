"""Tests for `control_plane.auth.audit.ControlPlaneAuditor`."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from charter.audit import AuditEntry
from charter.verifier import verify_audit_log
from control_plane.auth.audit import ControlPlaneAuditor, make_audit_emit


@pytest.mark.asyncio
async def test_emit_appends_hash_chained_entry(tmp_path: Path) -> None:
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    entry = await auditor.emit("auth.login.succeeded", {"sub": "auth0|alice"})

    assert isinstance(entry, AuditEntry)
    assert entry.action == "auth.login.succeeded"
    assert entry.payload == {"sub": "auth0|alice"}
    # First entry's previous_hash is the genesis (64 zeroes).
    assert entry.previous_hash == "0" * 64


@pytest.mark.asyncio
async def test_consecutive_emits_form_a_chain(tmp_path: Path) -> None:
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    first = await auditor.emit("auth.login.succeeded", {"sub": "a"})
    second = await auditor.emit("tenant.created", {"tenant_id": "01HXYZ"})

    assert second.previous_hash == first.entry_hash


@pytest.mark.asyncio
async def test_chain_verifies_via_charter_verifier(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    auditor = ControlPlaneAuditor(log_path=log_path)
    await auditor.emit("auth.login.succeeded", {"sub": "a"})
    await auditor.emit("tenant.created", {"tenant_id": "01HXYZ"})
    await auditor.emit("mfa.required.failure", {"sub": "b", "action": "manage_tenant"})

    result = verify_audit_log(log_path)
    assert result.valid is True
    assert result.entries_checked == 3


@pytest.mark.asyncio
async def test_concurrent_emits_are_serialized(tmp_path: Path) -> None:
    """50 concurrent emits must produce a clean chain — no race-induced corruption."""
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    coros = [auditor.emit("auth.login.succeeded", {"i": i}) for i in range(50)]
    entries = await asyncio.gather(*coros)

    # Chain links up by entry_hash regardless of which order asyncio chose.
    hashes = {entry.entry_hash for entry in entries}
    assert len(hashes) == 50
    result = verify_audit_log(tmp_path / "audit.jsonl")
    assert result.valid is True
    assert result.entries_checked == 50


@pytest.mark.asyncio
async def test_make_audit_emit_returns_callable_with_noop_shape(
    tmp_path: Path,
) -> None:
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    emit = make_audit_emit(auditor)
    await emit("auth.login.initiated", {})

    result = verify_audit_log(tmp_path / "audit.jsonl")
    assert result.valid is True
    assert result.entries_checked == 1


@pytest.mark.asyncio
async def test_log_path_parent_directory_is_created(tmp_path: Path) -> None:
    log_path = tmp_path / "nested" / "dir" / "audit.jsonl"
    auditor = ControlPlaneAuditor(log_path=log_path)
    await auditor.emit("auth.login.initiated", {})
    assert log_path.is_file()


@pytest.mark.asyncio
async def test_payload_is_preserved_verbatim(tmp_path: Path) -> None:
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    payload = {
        "sub": "auth0|alice",
        "tenant_id": "01HXYZTENANT0000000000000A",
        "amr": ["pwd", "mfa"],
        "nested": {"key": "value", "n": 1},
    }
    entry = await auditor.emit("auth.login.succeeded", payload)
    assert entry.payload == payload


@pytest.mark.asyncio
async def test_agent_and_run_id_are_set_on_entries(tmp_path: Path) -> None:
    auditor = ControlPlaneAuditor(
        log_path=tmp_path / "audit.jsonl", agent="custom-plane", run_id="run-abc"
    )
    entry = await auditor.emit("auth.login.initiated", {})
    assert entry.agent == "custom-plane"
    assert entry.run_id == "run-abc"


@pytest.mark.asyncio
async def test_distinct_events_keep_their_action_names(tmp_path: Path) -> None:
    auditor = ControlPlaneAuditor(log_path=tmp_path / "audit.jsonl")
    actions = [
        "auth.login.succeeded",
        "auth.login.failed",
        "tenant.created",
        "user.provisioned.scim",
        "mfa.required.failure",
        "tenant.suspended",
    ]
    for action in actions:
        await auditor.emit(action, {})

    # Read the log back and confirm every action name was preserved.
    log_path = tmp_path / "audit.jsonl"
    seen: list[str] = []
    for line in log_path.read_text().splitlines():
        if line.strip():
            seen.append(AuditEntry.from_json(line).action)
    assert seen == actions
