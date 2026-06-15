"""gitleaks normalizer + redaction tests (D.14 B-1 PR3, ADR-015)."""

from __future__ import annotations

import json

import pytest
from appsec.normalizers.gitleaks_secrets import (
    gitleaks_to_secret_hits,
    render_code_secrets_json,
)
from appsec.tools import gitleaks_runner
from appsec.tools.gitleaks_runner import GitleaksResult

pytestmark = pytest.mark.asyncio

_PLAINTEXT = "AKIAIOSFODNN7EXAMPLE"  # AWS docs example, test fixture

_GITLEAKS_FINDING = {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Token",
    "File": "src/config.py",
    "StartLine": 12,
    "EndLine": 12,
    "Secret": _PLAINTEXT,
    "Match": f"AWS_KEY={_PLAINTEXT}",
}


def test_normalizes_and_redacts() -> None:
    hits = gitleaks_to_secret_hits(GitleaksResult(payload=[_GITLEAKS_FINDING]))
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == "aws-access-token"
    assert hit.category == "code_secret"
    assert hit.severity == "HIGH"
    assert hit.target == "src/config.py"
    assert hit.start_line == 12
    # Redaction: no field carries the plaintext secret.
    assert _PLAINTEXT not in repr(hit)


def test_rendered_handoff_never_contains_plaintext() -> None:
    hits = gitleaks_to_secret_hits(GitleaksResult(payload=[_GITLEAKS_FINDING]))
    raw = render_code_secrets_json(run_id="run-1", hits=hits)
    text = raw.decode("utf-8")
    assert _PLAINTEXT not in text
    payload = json.loads(text)
    assert payload["agent"] == "appsec"
    assert payload["run_id"] == "run-1"
    assert payload["secrets"][0]["rule_id"] == "aws-access-token"
    assert "secret" not in payload["secrets"][0]
    assert "match" not in payload["secrets"][0]


def test_empty_payload_yields_no_hits() -> None:
    assert gitleaks_to_secret_hits(GitleaksResult(payload=[])) == []


async def test_missing_binary_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_runner.shutil, "which", lambda _name: None)
    result = await gitleaks_runner.run_gitleaks("/nonexistent")
    assert result.binary_present is False
    assert result.payload == []
