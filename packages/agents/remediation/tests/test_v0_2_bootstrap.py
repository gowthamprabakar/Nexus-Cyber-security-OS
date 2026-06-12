"""remediation v0.2 Task 1 — bootstrap + SAFETY-CRITICAL re-verification (Cycle 16)."""

from __future__ import annotations

from pathlib import Path

import remediation
from remediation.action_classes import ACTION_CLASS_REGISTRY
from remediation.schemas import OCSF_CLASS_UID, RemediationMode

_PKG = Path(remediation.__file__).parent


def test_version_is_v0_2() -> None:
    assert remediation.__version__ == "0.2.0"


def test_pyproject_version_bumped() -> None:
    text = (_PKG.parents[1] / "pyproject.toml").read_text()
    assert 'version = "0.2.0"' in text


def test_sole_ocsf_2007_emitter() -> None:
    assert OCSF_CLASS_UID == 2007


def test_three_operational_modes() -> None:
    assert {m.value for m in RemediationMode} == {"recommend", "dry_run", "execute"}


def test_five_v0_1_action_classes_present() -> None:
    # M3 expands this to 7; bootstrap pins the v0.1 baseline.
    assert len(ACTION_CLASS_REGISTRY) == 5


def test_changelog_safety_critical_banner() -> None:
    changelog = (_PKG.parents[1] / "CHANGELOG.md").read_text()
    assert "SAFETY-CRITICAL" in changelog


def test_fifteen_eval_cases_present() -> None:
    cases = list((_PKG.parents[1] / "eval" / "cases").glob("*.yaml"))
    assert len(cases) == 15
