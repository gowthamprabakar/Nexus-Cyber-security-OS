"""v0.2.5 Skill Optimization — bootstrap smoke tests (Task 1).

Mirrors ``test_g2_bootstrap.py``. Verifies:

1.  v0.2.5 version is ``0.2.5`` (``meta_harness.__version__``).
2.  pyproject.toml version agrees with ``__version__``.
3.  Existing v0.2 + G1 + G2 modules import cleanly after the version bump.
4.  CLI + eval-runner entry-points still registered.
5.  The ``[dspy]`` optional-dependency group is declared with DSPy + GEPA.
6.  ``import meta_harness`` works WITHOUT the ``[dspy]`` extra — no core
    module hard-imports DSPy (backwards-compat; the extra is opt-in).
7.  DSPy + GEPA import smoke when the extra IS installed (skipped otherwise).

NO substrate touch, NO DSPy compilation code (Tasks 2/4+), NO new audit
constants — Task 1 only wires the version + optional-dependency group.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "meta_harness"

_EXPECTED_VERSION = "0.2.5"


def _pyproject() -> dict[str, Any]:
    with open(_PYPROJECT, "rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def test_v0_2_5_version_is_0_2_5() -> None:
    """Bootstrap gate — ``__version__`` wired to 0.2.5 (v0.2.5 cycle)."""
    import meta_harness

    assert hasattr(meta_harness, "__version__")
    assert isinstance(meta_harness.__version__, str)
    assert meta_harness.__version__ == _EXPECTED_VERSION, (
        f"Expected {_EXPECTED_VERSION} (v0.2.5), got {meta_harness.__version__}"
    )


def test_v0_2_5_pyproject_version_matches() -> None:
    """Bootstrap gate — pyproject.toml version agrees with ``__version__``."""
    import meta_harness

    pyproject_version = _pyproject()["project"]["version"]
    assert pyproject_version == meta_harness.__version__, (
        f"pyproject.toml {pyproject_version} != __version__ {meta_harness.__version__}"
    )
    assert pyproject_version == _EXPECTED_VERSION


# ---------------------------------------------------------------------------
# Module import integrity
# ---------------------------------------------------------------------------


def test_v0_2_5_existing_modules_import_cleanly() -> None:
    """All v0.2 + G1 + G2 modules still import after the version bump."""
    from meta_harness import (  # noqa: F401
        audit_emit,
        effectiveness_compat,
        effectiveness_store,
        schemas,
        skill_adoption,
        skill_approval,
        skill_discovery,
        skill_effectiveness,
        skill_eval_gate,
        skill_feedback,
        skill_format,
        skill_lifecycle,
        skill_outcome,
        skill_registry,
        skill_triggers,
        skill_writer,
    )


def test_v0_2_5_cli_and_eval_entry_points_still_registered() -> None:
    """Entry-points still registered after the version bump."""
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    assert "meta_harness" in {ep.name for ep in runners}, "eval-runner entry-point missing"

    scripts = entry_points(group="console_scripts")
    assert "meta-harness" in {ep.name for ep in scripts}, "CLI script entry-point missing"


# ---------------------------------------------------------------------------
# Optional-dependency group ([dspy])
# ---------------------------------------------------------------------------


def test_dspy_optional_group_declared() -> None:
    """The ``[dspy]`` optional-dependency group exists and names DSPy + GEPA."""
    optional = _pyproject()["project"].get("optional-dependencies", {})
    assert "dspy" in optional, "missing [project.optional-dependencies] dspy group"
    pkgs = " ".join(optional["dspy"]).lower()
    assert "dspy" in pkgs, f"dspy group must include DSPy: {optional['dspy']}"
    assert "gepa" in pkgs, f"dspy group must include GEPA: {optional['dspy']}"


def test_meta_harness_imports_without_dspy_extra() -> None:
    """Backwards-compat — importing the package must NOT require the ``[dspy]``
    extra. Task 1 adds the dependency group only; no core module imports DSPy
    at load time, so the package works whether or not the extra is installed."""
    import importlib

    import meta_harness

    importlib.reload(meta_harness)  # fresh import; must not raise on missing dspy

    # No Task-1 source file may hard-import dspy/gepa at module top level
    # (the optional dep is wired in Tasks 4+, behind lazy imports).
    offenders: list[str] = []
    for path in _SRC_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import dspy", "from dspy", "import gepa", "from gepa")):
                offenders.append(f"{path.name}: {stripped}")
    assert not offenders, f"unexpected top-level DSPy/GEPA imports in Task 1: {offenders}"


def test_dspy_and_gepa_importable_when_extra_installed() -> None:
    """When the ``[dspy]`` extra is installed (CI runs ``uv sync --all-extras``),
    DSPy and GEPA import cleanly. Skipped for dev envs without the extra."""
    dspy = pytest.importorskip("dspy")
    gepa = pytest.importorskip("gepa")
    assert dspy is not None
    assert gepa is not None
