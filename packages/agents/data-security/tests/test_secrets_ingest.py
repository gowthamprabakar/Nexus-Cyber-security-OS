"""A-2.4 (ADR-015) — DSPM ingests D.1 secrets-in-runtime → OCSF 2003.

Covers reading D.1's redacted ``runtime_secrets.json`` sibling artifact, mapping
it to OCSF 2003 ``SECRET_EXPOSED_IN_RUNTIME`` findings, graceful handling of
missing/empty artifacts, and the redaction-integrity guarantee (no plaintext).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from data_security.schemas import DataSecurityFindingType
from data_security.secrets_ingest import (
    RUNTIME_SECRETS_FILENAME,
    ingest_runtime_secret_findings,
    read_runtime_secrets,
    secrets_to_findings,
)
from shared.fabric.envelope import NexusEnvelope

_DETECTED_AT = datetime(2026, 6, 15, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d5d5",
        tenant_id="acme",
        agent_id="data-security",
        nlah_version="d5-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _write_artifact(workspace: Path, secrets: list[dict[str, object]]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "0.1",
        "agent": "vulnerability",
        "run_id": "run-1",
        "secrets": secrets,
    }
    (workspace / RUNTIME_SECRETS_FILENAME).write_text(json.dumps(payload), encoding="utf-8")


_HIT = {
    "rule_id": "aws-access-key-id",
    "category": "AWS",
    "severity": "CRITICAL",
    "title": "AWS Access Key ID",
    "target": "app/.env",
    "start_line": 3,
    "end_line": 3,
}


def test_read_missing_artifact_is_empty(tmp_path: Path) -> None:
    assert read_runtime_secrets(tmp_path) == []


def test_read_malformed_artifact_is_empty(tmp_path: Path) -> None:
    (tmp_path / RUNTIME_SECRETS_FILENAME).write_text("{not json", encoding="utf-8")
    assert read_runtime_secrets(tmp_path) == []


def test_ingest_none_workspace_is_empty() -> None:
    assert (
        ingest_runtime_secret_findings(None, envelope=_envelope(), detected_at=_DETECTED_AT) == []
    )


def test_secrets_to_findings_emits_ocsf_2003_discriminator() -> None:
    findings = secrets_to_findings([_HIT], envelope=_envelope(), detected_at=_DETECTED_AT)
    assert len(findings) == 1
    ocsf = findings[0].to_dict()
    assert ocsf["class_uid"] == 2003
    # Discriminator is carried in evidence.source_finding_type (the fleet pattern).
    assert ocsf["evidences"][0]["source_finding_type"] == (
        DataSecurityFindingType.SECRET_EXPOSED_IN_RUNTIME.value
    )
    assert findings[0].finding_id.startswith("CSPM-RUNTIME-SECRET-")


def test_end_to_end_ingest_from_workspace(tmp_path: Path) -> None:
    _write_artifact(tmp_path, [_HIT])
    findings = ingest_runtime_secret_findings(
        tmp_path, envelope=_envelope(), detected_at=_DETECTED_AT
    )
    assert len(findings) == 1
    ocsf = findings[0].to_dict()
    assert ocsf["compliance"]["control"] == "secret_exposed_in_runtime"


def test_no_plaintext_in_emitted_finding(tmp_path: Path) -> None:
    # The D.1 artifact is already redacted, but assert nothing secret-shaped
    # is reconstructed in the OCSF payload.
    _write_artifact(tmp_path, [_HIT])
    findings = ingest_runtime_secret_findings(
        tmp_path, envelope=_envelope(), detected_at=_DETECTED_AT
    )
    serialized = json.dumps(findings[0].to_dict())
    assert "AKIA" not in serialized
    assert "match" not in serialized.lower()
