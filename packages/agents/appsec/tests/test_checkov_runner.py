"""Checkov runner tests (D.14 B-1 PR2) — graceful binary-absence."""

from __future__ import annotations

from pathlib import Path

import pytest
from appsec.tools import checkov_runner

pytestmark = pytest.mark.asyncio


async def test_missing_binary_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(checkov_runner.shutil, "which", lambda _name: None)
    result = await checkov_runner.run_checkov(str(tmp_path))
    assert result.binary_present is False
    assert result.payload == {}
