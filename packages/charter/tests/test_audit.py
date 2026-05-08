"""Tests for the audit log — append-only with SHA-256 hash chain."""

import json
from pathlib import Path

from charter.audit import AuditLog


def test_append_first_entry_links_to_genesis(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="cloud_posture", run_id="r1")
    entry = log.append(action="tool_call", payload={"tool": "echo", "kwargs": {"value": "hi"}})
    assert entry.previous_hash == "0" * 64  # genesis link


def test_append_chains_hashes(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="cloud_posture", run_id="r1")
    e1 = log.append(action="tool_call", payload={"tool": "a"})
    e2 = log.append(action="tool_call", payload={"tool": "b"})
    assert e2.previous_hash == e1.entry_hash
    assert e1.entry_hash != e2.entry_hash


def test_log_persists_to_disk(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    log.append(action="tool_call", payload={"tool": "a"})
    log.append(action="tool_call", payload={"tool": "b"})
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["action"] == "tool_call"
    assert parsed[1]["previous_hash"] == parsed[0]["entry_hash"]


def test_log_resumes_chain_from_existing_file(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log1 = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    e1 = log1.append(action="tool_call", payload={"tool": "a"})
    log2 = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    e2 = log2.append(action="tool_call", payload={"tool": "b"})
    assert e2.previous_hash == e1.entry_hash


def test_append_includes_timestamp(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="x", run_id="r1")
    entry = log.append(action="x", payload={})
    assert entry.timestamp.endswith("Z") or "+" in entry.timestamp
