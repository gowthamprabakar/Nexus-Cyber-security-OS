"""compliance v0.2 Task 17 — per-framework evidence export tests."""

from __future__ import annotations

import json

from compliance.evidence.bundle import build_evidence_bundle, build_evidence_entry
from compliance.evidence.chain import build_manifest
from compliance.evidence.export import export_json, export_report_text

_TS = "2026-06-11T12:00:00+00:00"


def _bundle_and_manifest():
    entries = [
        build_evidence_entry(
            framework_id="cis_aws_v3",
            control_id="1.4",
            status="pass",
            source_finding_ids=["F-1"],
            timestamp=_TS,
        ),
        build_evidence_entry(
            framework_id="cis_aws_v3",
            control_id="5.2",
            status="fail",
            source_finding_ids=["F-2"],
            timestamp=_TS,
        ),
    ]
    bundle = build_evidence_bundle(framework_id="cis_aws_v3", generated_at=_TS, entries=entries)
    manifest = build_manifest(
        framework_id="cis_aws_v3", entry_hashes=[e.entry_hash for e in entries]
    )
    return bundle, manifest


def test_export_json_parses() -> None:
    bundle, manifest = _bundle_and_manifest()
    parsed = json.loads(export_json(bundle, manifest))
    assert parsed["bundle"]["framework_id"] == "cis_aws_v3"
    assert parsed["bundle"]["entry_count"] == 2
    assert parsed["manifest"]["signed_by"] == "compliance-v0.2-placeholder"


def test_export_json_deterministic() -> None:
    bundle, manifest = _bundle_and_manifest()
    assert export_json(bundle, manifest) == export_json(bundle, manifest)


def test_report_text_has_framework_and_counts() -> None:
    bundle, manifest = _bundle_and_manifest()
    text = export_report_text(bundle, manifest)
    assert "Compliance Evidence — cis_aws_v3" in text
    assert "PASS 1 / FAIL 1" in text


def test_report_text_has_control_rows() -> None:
    bundle, manifest = _bundle_and_manifest()
    text = export_report_text(bundle, manifest)
    assert "| 1.4 | PASS |" in text and "| 5.2 | FAIL |" in text


def test_report_text_has_signed_manifest() -> None:
    bundle, manifest = _bundle_and_manifest()
    text = export_report_text(bundle, manifest)
    assert "Signed manifest" in text and manifest.chain_head in text


def test_empty_bundle_export() -> None:
    bundle = build_evidence_bundle(framework_id="cis_gcp_v2", generated_at=_TS, entries=[])
    manifest = build_manifest(framework_id="cis_gcp_v2", entry_hashes=[])
    text = export_report_text(bundle, manifest)
    assert "Controls: 0" in text
