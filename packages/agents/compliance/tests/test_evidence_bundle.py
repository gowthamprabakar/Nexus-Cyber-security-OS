"""compliance v0.2 Task 15 — audit-ready evidence bundle schema tests (Q6)."""

from __future__ import annotations

from compliance.evidence.bundle import (
    EvidenceEntry,
    build_evidence_bundle,
    build_evidence_entry,
)

_TS = "2026-06-11T12:00:00+00:00"


def _entry(control_id: str = "1.4", status: str = "pass") -> EvidenceEntry:
    return build_evidence_entry(
        framework_id="cis_aws_v3",
        control_id=control_id,
        status=status,
        source_finding_ids=["F-1"],
        timestamp=_TS,
    )


def test_entry_has_hash() -> None:
    e = _entry()
    assert len(e.entry_hash) == 64 and e.control_id == "1.4" and e.status == "pass"


def test_hash_is_deterministic() -> None:
    assert _entry().entry_hash == _entry().entry_hash


def test_hash_changes_with_content() -> None:
    assert _entry(status="pass").entry_hash != _entry(status="fail").entry_hash
    assert _entry(control_id="1.4").entry_hash != _entry(control_id="1.5").entry_hash


def test_entry_to_dict_roundtrip() -> None:
    d = _entry().to_dict()
    assert d["framework_id"] == "cis_aws_v3" and d["entry_hash"]
    assert d["source_finding_ids"] == ["F-1"]


def test_content_excludes_hash() -> None:
    e = _entry()
    assert "entry_hash" not in e.content()


def test_bundle_to_dict() -> None:
    bundle = build_evidence_bundle(
        framework_id="cis_aws_v3",
        generated_at=_TS,
        entries=[_entry("1.4", "pass"), _entry("5.2", "fail")],
    )
    d = bundle.to_dict()
    assert d["entry_count"] == 2 and d["framework_id"] == "cis_aws_v3"
    assert {e["control_id"] for e in d["entries"]} == {"1.4", "5.2"}


def test_empty_bundle() -> None:
    bundle = build_evidence_bundle(framework_id="cis_aws_v3", generated_at=_TS, entries=[])
    assert bundle.to_dict()["entry_count"] == 0
