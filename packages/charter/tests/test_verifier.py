"""Tests for AuditLog integrity verification."""

import json
from pathlib import Path

from charter.audit import AuditLog
from charter.verifier import verify_audit_log


def test_clean_log_verifies(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})
    log.append(action="c", payload={})
    result = verify_audit_log(tmp_path / "audit.jsonl")
    assert result.valid is True
    assert result.entries_checked == 3


def test_tampered_payload_fails_verification(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={"v": 1})
    log.append(action="b", payload={"v": 2})

    raw = log_path.read_text().strip().split("\n")
    parsed = [json.loads(line) for line in raw]
    parsed[0]["payload"]["v"] = 999  # tamper
    log_path.write_text(
        "\n".join(json.dumps(p, sort_keys=True, separators=(",", ":")) for p in parsed) + "\n"
    )

    result = verify_audit_log(log_path)
    assert result.valid is False
    assert result.broken_at == 0


def test_broken_chain_link_fails(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})

    raw = log_path.read_text().strip().split("\n")
    parsed = [json.loads(line) for line in raw]
    parsed[1]["previous_hash"] = "f" * 64  # break the chain
    log_path.write_text(
        "\n".join(json.dumps(p, sort_keys=True, separators=(",", ":")) for p in parsed) + "\n"
    )

    result = verify_audit_log(log_path)
    assert result.valid is False
    assert result.broken_at == 1
