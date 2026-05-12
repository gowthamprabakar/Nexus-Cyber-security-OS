"""Tests for `audit.tools.jsonl_reader` (F.6 Task 6).

Production contract:

- Async wrapper per ADR-005 — filesystem read happens via
  `asyncio.to_thread` because the SDK is sync.
- Reads `audit.jsonl` files emitted by `charter.audit.AuditLog`. Each
  line is a JSON `AuditEntry` shape: `timestamp`, `agent`, `run_id`,
  `action`, `payload`, `previous_hash`, `entry_hash`.
- Returns `tuple[AuditEvent, ...]` — the F.6 wire shape from Task 4.
- Maps `AuditEntry.run_id` → `correlation_id` (charter's audit log
  carries run_id as the chain identifier; F.6 promotes it).
- Inherits a `source = "jsonl:<path>"` tag so the AuditStore can
  identify where each event came from.
- Caller supplies `tenant_id` — the underlying `charter.audit.AuditLog`
  doesn't carry tenant, so the reader stamps it.
- Tolerates malformed lines per the D.3 pattern: a single bad line
  doesn't crash the whole ingest.
- Empty file returns an empty tuple; missing file raises.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from audit.tools.jsonl_reader import AuditJsonlError, audit_jsonl_read

_TENANT_A = "01HV0T0000000000000000TENA"
_HEX64_A = "a" * 64
_HEX64_B = "b" * 64
_HEX64_C = "c" * 64


def _entry(
    *,
    run_id: str = "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    agent: str = "cloud_posture",
    action: str = "episode_appended",
    previous_hash: str = _HEX64_A,
    entry_hash: str = _HEX64_B,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "agent": agent,
        "run_id": run_id,
        "action": action,
        "payload": payload or {"episode_id": 1},
        "previous_hash": previous_hash,
        "entry_hash": entry_hash,
    }


def _write_jsonl(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_audit_jsonl_read_returns_tuple_of_audit_events(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    _write_jsonl(file, [_entry(entry_hash=_HEX64_B), _entry(entry_hash=_HEX64_C)])

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert isinstance(events, tuple)
    assert len(events) == 2
    assert events[0].entry_hash == _HEX64_B


@pytest.mark.asyncio
async def test_audit_jsonl_read_maps_run_id_to_correlation_id(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    _write_jsonl(file, [_entry(run_id="01J7N4Y0A2L9SQWRJK3U9ECIGA")])

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert events[0].correlation_id == "01J7N4Y0A2L9SQWRJK3U9ECIGA"


@pytest.mark.asyncio
async def test_audit_jsonl_read_maps_agent_to_agent_id(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    _write_jsonl(file, [_entry(agent="runtime_threat")])

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert events[0].agent_id == "runtime_threat"


@pytest.mark.asyncio
async def test_audit_jsonl_read_stamps_tenant_id(tmp_path: Path) -> None:
    """The charter audit log doesn't carry tenant_id; the reader stamps
    it from the caller-supplied argument.
    """
    file = tmp_path / "audit.jsonl"
    _write_jsonl(file, [_entry()])

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert events[0].tenant_id == _TENANT_A


@pytest.mark.asyncio
async def test_audit_jsonl_read_stamps_source_tag(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    _write_jsonl(file, [_entry()])

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert events[0].source == f"jsonl:{file}"


# ---------------------------- malformed-line tolerance -----------------


@pytest.mark.asyncio
async def test_audit_jsonl_read_tolerates_malformed_lines(tmp_path: Path) -> None:
    """A single bad line in the file must not crash the whole ingest —
    Falco / charter audit logs occasionally interleave non-JSON noise.
    """
    file = tmp_path / "audit.jsonl"
    file.write_text(
        "\n".join(
            [
                json.dumps(_entry(entry_hash=_HEX64_B)),
                "this is not json {{{",
                json.dumps(_entry(entry_hash=_HEX64_C)),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    # Bad line dropped, two clean entries land.
    assert len(events) == 2


@pytest.mark.asyncio
async def test_audit_jsonl_read_tolerates_blank_lines(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    file.write_text(
        json.dumps(_entry()) + "\n\n   \n" + json.dumps(_entry(entry_hash=_HEX64_C)) + "\n",
        encoding="utf-8",
    )

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert len(events) == 2


@pytest.mark.asyncio
async def test_audit_jsonl_read_skips_entries_with_malformed_hashes(
    tmp_path: Path,
) -> None:
    """A line that round-trips through JSON but fails AuditEvent validation
    (e.g. non-hex hash) is dropped, not raised.
    """
    file = tmp_path / "audit.jsonl"
    _write_jsonl(
        file,
        [
            _entry(entry_hash=_HEX64_B),
            _entry(entry_hash="not-a-hex-hash-zzz" * 4),  # 64-char but non-hex
            _entry(entry_hash=_HEX64_C),
        ],
    )

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert len(events) == 2


# ---------------------------- empty + missing ---------------------------


@pytest.mark.asyncio
async def test_audit_jsonl_read_empty_file_returns_empty_tuple(tmp_path: Path) -> None:
    file = tmp_path / "audit.jsonl"
    file.write_text("", encoding="utf-8")

    events = await audit_jsonl_read(path=file, tenant_id=_TENANT_A)
    assert events == ()


@pytest.mark.asyncio
async def test_audit_jsonl_read_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AuditJsonlError):
        await audit_jsonl_read(path=tmp_path / "does-not-exist.jsonl", tenant_id=_TENANT_A)
