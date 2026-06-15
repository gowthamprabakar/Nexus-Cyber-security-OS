"""Semgrep SAST normalizer + OCSF 2003 emission tests (D.14 B-1 PR8)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from appsec.normalizers.semgrep_sast import semgrep_to_findings
from appsec.ocsf.emission import finding_to_ocsf
from appsec.schemas import AppSecFindingType, Severity
from appsec.tools import semgrep_runner

pytestmark = pytest.mark.asyncio

_RESULT = {
    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
    "path": "/src/app.py",
    "start": {"line": 10, "col": 5},
    "end": {"line": 10, "col": 40},
    "extra": {"message": "Detected subprocess call with shell=True", "severity": "ERROR"},
}
_PAYLOAD = {"results": [_RESULT], "errors": []}


def test_normalizes_results() -> None:
    findings = semgrep_to_findings(_PAYLOAD, repo_slug="github/acme/api")
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type is AppSecFindingType.SAST_FINDING
    assert f.rule_id == "python.lang.security.audit.dangerous-subprocess-use"
    assert f.severity is Severity.HIGH  # ERROR → HIGH
    assert f.location == "src/app.py:10"


def test_severity_mapping_and_default() -> None:
    warn = {**_RESULT, "extra": {"message": "m", "severity": "WARNING"}}
    none = {**_RESULT, "extra": {"message": "m"}}  # missing severity
    sev_w = semgrep_to_findings({"results": [warn]}, repo_slug="r")[0].severity
    sev_n = semgrep_to_findings({"results": [none]}, repo_slug="r")[0].severity
    assert sev_w is Severity.MEDIUM
    assert sev_n is Severity.MEDIUM  # default


def test_empty_and_malformed() -> None:
    assert semgrep_to_findings({}, repo_slug="r") == []
    assert semgrep_to_findings({"results": "bad"}, repo_slug="r") == []


def test_ocsf_emission_2003_with_sast_discriminator() -> None:
    finding = semgrep_to_findings(_PAYLOAD, repo_slug="github/acme/api")[0]
    ocsf = finding_to_ocsf(
        finding, customer_id="cust", run_id="run-1", detected_at=datetime(2026, 6, 15, tzinfo=UTC)
    )
    assert ocsf["class_uid"] == 2003
    assert ocsf["finding_info"]["types"] == ["appsec_sast_finding"]
    assert ocsf["evidences"][0]["source_finding_type"] == "appsec_sast_finding"


async def test_missing_binary_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda _name: None)
    result = await semgrep_runner.run_semgrep("/repo")
    assert result.binary_present is False
    assert result.payload == {}
