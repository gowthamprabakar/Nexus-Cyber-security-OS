"""G2 bootstrap smoke tests — Task 1 (version bump + regression gates).

12 tests:

1.  G2 version is 0.2.2 (``meta_harness.__version__``).
2.  G2 pyproject version matches ``__version__`` (reads from source file).
3.  Existing v0.2 + G1 modules import cleanly after version bump.
4.  G2 plan doc exists at the expected path and names key conventions.
5.  **WI-1 / substrate seal** — ``git diff --stat packages/shared/`` empty (charter/ arm
    lifted for the approved ADR-016 tool-proxy cycle; see the test's scope note).
6.  **Safety gate 1 (novelty)** — ``compute_tool_sequence_hash`` deterministic.
7.  **Safety gate 2 (trust-boundary)** — ``_FORBIDDEN_SUBSCRIPTIONS`` still holds.
8.  **Safety gate 3 (eval-gate)** — ``run_skill_eval_gate`` importable; no ``--force`` in CLI.
9.  **Safety gate 4 (class-registry)** — ``SkillClassRegistry`` importable.
10. **Safety gate 5 (routing enforcement)** — promote/reject/notify importable.
11. **G1 audit vocabulary** — all 6 G1 audit actions are defined.
12. **G1 eval integrity** — 20 eval case YAML files exist; G1 test file imports cleanly.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "meta_harness"


def _iter_source_files() -> list[Path]:
    return sorted(p for p in _SRC_ROOT.rglob("*.py") if p.is_file())


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def test_g2_version_is_0_2_2() -> None:
    """Bootstrap gate — ``__version__`` wired to 0.2.2 (G2 cycle)."""
    import meta_harness

    assert hasattr(meta_harness, "__version__")
    assert isinstance(meta_harness.__version__, str)
    assert meta_harness.__version__ == "0.2.5", (
        f"Expected 0.2.5 (live; G2 shipped 0.2.2), got {meta_harness.__version__}"
    )


def test_g2_pyproject_version_matches() -> None:
    """Bootstrap gate — pyproject.toml version agrees with ``__version__``."""
    import meta_harness

    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    pyproject_version = data["project"]["version"]
    assert pyproject_version == meta_harness.__version__, (
        f"pyproject.toml {pyproject_version} != __version__ {meta_harness.__version__}"
    )
    assert pyproject_version == "0.2.5"


# ---------------------------------------------------------------------------
# Module import integrity
# ---------------------------------------------------------------------------


def test_g2_existing_modules_import_cleanly() -> None:
    """All v0.2 + G1 modules still import after version bump."""
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


def test_g2_cli_and_eval_entry_points_still_registered() -> None:
    """Entry-points still registered after version bump."""
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "meta_harness" in names, "eval-runner entry-point missing"

    scripts = entry_points(group="console_scripts")
    script_names = {ep.name for ep in scripts}
    assert "meta-harness" in script_names, "CLI script entry-point missing"


# ---------------------------------------------------------------------------
# Plan doc gate
# ---------------------------------------------------------------------------


def test_g2_plan_doc_exists_and_names_scope() -> None:
    """G2 plan doc must exist at the expected path and name key conventions."""
    plan_path = _REPO_ROOT / "docs" / "superpowers" / "plans" / "2026-05-25-g2-skill-selection.md"
    assert plan_path.is_file(), f"G2 plan doc not found at {plan_path}"
    plan_text = plan_path.read_text(encoding="utf-8")
    # G2 scope signals
    assert "skill selection" in plan_text.lower()
    assert "trigger_source" in plan_text  # G2-Q1 resolution
    assert "effectiveness" in plan_text.lower()  # G1 consumption
    assert "Hermes" in plan_text  # Hermes-pattern architecture
    assert "no embeddings" in plan_text.lower() or "NO embeddings" in plan_text
    assert "LLM" in plan_text  # LLM-driven selection
    # Task count
    assert "8 tasks" in plan_text.lower() or "8/8" in plan_text.lower()


# ---------------------------------------------------------------------------
# WI-1 — substrate sealed
# ---------------------------------------------------------------------------


def test_g2_wi1_substrate_sealed_bootstrap() -> None:
    """WI-1 — G2 work must not touch the ``packages/shared/`` substrate.

    G2 Task 2 is the single planned SAFETY-CRITICAL substrate touch
    (trigger_source on ExecutionContract). At bootstrap, zero substrate
    changes are expected.

    Scope note (NLAH Full Backfill cycle, 2026-06-09): ``packages/charter/`` is
    under an approved, cross-cutting substrate modification — the tool-proxy hard
    boundary (ADR-016, Milestone 1). That change is governed by its own guards
    (``charter/tests/test_tool_proxy.py`` + ``test_tool_import_guard.py``), not by
    this G2 bootstrap seal. The charter arm of this seal is therefore lifted for
    the duration of that cycle; the ``packages/shared/`` arm remains in force (the
    NLAH cycle's scope rules forbid touching shared/, and it does not).
    """
    import shutil
    import subprocess

    git = shutil.which("git")
    assert git is not None, "git not found on PATH"
    # CI shallow clones don't have origin/main — fetch it first.
    subprocess.run(  # noqa: S603
        [git, "fetch", "origin", "main"],
        check=False,
        capture_output=True,
        cwd=_REPO_ROOT,
    )
    result = subprocess.run(  # noqa: S603
        [git, "diff", "--stat", "origin/main", "--", "packages/shared/"],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0
    diff_output = result.stdout.strip()
    assert not diff_output, f"WI-1 violation — must not touch shared/ substrate.\n{diff_output}"


# ---------------------------------------------------------------------------
# Safety gate 1 — novelty (Q3 trigger: hash-novel tool sequence)
# ---------------------------------------------------------------------------


def test_g2_safety_gate_1_novelty_trigger_intact() -> None:
    """Safety gate 1 — 3-condition trigger gate still importable and
    functional shape intact."""
    from meta_harness.skill_triggers import compute_tool_sequence_hash

    h1 = compute_tool_sequence_hash(["tool_a", "tool_b", "tool_c"])
    h2 = compute_tool_sequence_hash(["tool_a", "tool_b", "tool_c"])
    assert h1 == h2
    assert isinstance(h1, str) and len(h1) == 64  # SHA-256


# ---------------------------------------------------------------------------
# Safety gate 2 — trust-boundary (Q-ARCH-1: _FORBIDDEN_SUBSCRIPTIONS)
# ---------------------------------------------------------------------------


def test_g2_safety_gate_2_forbidden_subscriptions_holds() -> None:
    """Safety gate 2 — meta_harness still in _FORBIDDEN_SUBSCRIPTIONS."""
    from shared.fabric.client import _FORBIDDEN_SUBSCRIPTIONS

    assert "meta_harness" in _FORBIDDEN_SUBSCRIPTIONS, (
        "Q-ARCH-1 violation — meta_harness must remain forbidden subscriber"
    )
    assert _FORBIDDEN_SUBSCRIPTIONS["meta_harness"] == frozenset({"claims.>"})


# ---------------------------------------------------------------------------
# Safety gate 3 — eval-gate mandatory, no --force
# ---------------------------------------------------------------------------


def test_g2_safety_gate_3_no_force_flag_in_cli() -> None:
    """Safety gate 3 — CLI source must not contain a --force flag."""
    cli_path = _SRC_ROOT / "cli.py"
    assert cli_path.is_file()
    cli_text = cli_path.read_text(encoding="utf-8")
    assert "--force" not in cli_text, "Safety gate 3 violation — --force flag found in CLI."


def test_g2_safety_gate_3_eval_gate_module_intact() -> None:
    """Safety gate 3 — eval-gate module importable."""
    from meta_harness.skill_eval_gate import (  # noqa: F401
        run_skill_eval_gate,
        with_candidate_skill_overlay,
    )


# ---------------------------------------------------------------------------
# Safety gate 4 — class-registry (first-of-class operator approval)
# ---------------------------------------------------------------------------


def test_g2_safety_gate_4_class_registry_intact() -> None:
    """Safety gate 4 — skill-class registry importable."""
    from meta_harness.skill_registry import SkillClassRegistry  # noqa: F401


# ---------------------------------------------------------------------------
# Safety gate 5 — routing enforcement
# ---------------------------------------------------------------------------


def test_g2_safety_gate_5_routing_paths_intact() -> None:
    """Safety gate 5 — promote, reject, notification importable."""
    from meta_harness.skill_approval import (  # noqa: F401
        _promote_to_canonical,
        reject_candidate,
        write_candidate_notification,
    )


# ---------------------------------------------------------------------------
# G1 audit vocabulary — all 6 actions defined
# ---------------------------------------------------------------------------


def test_g2_g1_audit_vocabulary_complete() -> None:
    """All 6 G1 audit actions are defined and have correct shape."""
    from shared.skill_telemetry import (
        ACTION_AGENT_SKILL_CONTRIBUTED,
        ACTION_AGENT_SKILL_LOADED,
        ACTION_AGENT_SKILL_OPERATOR_RATED,
        ACTION_AGENT_SKILL_OUTCOME_CORRELATED,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
    )

    actions = {
        ACTION_AGENT_SKILL_LOADED,
        ACTION_AGENT_SKILL_CONTRIBUTED,
        ACTION_AGENT_SKILL_OUTCOME_CORRELATED,
        ACTION_AGENT_SKILL_OPERATOR_RATED,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
    }
    assert len(actions) == 6, f"Expected 6 G1 audit actions, got {len(actions)}"
    for action in actions:
        assert isinstance(action, str)
        assert len(action) > 0


# ---------------------------------------------------------------------------
# G1 + G2 eval integrity — 25 cases exist; G1/G2 test files import cleanly
# ---------------------------------------------------------------------------


def test_g2_g1_eval_cases_still_load() -> None:
    """All 25 eval case YAML files exist (15 v0.2 + 5 G1 + 5 G2) and the
    G1/G2 test modules import."""
    cases_dir = _SRC_ROOT.parent.parent / "eval" / "cases"
    yaml_files = sorted(cases_dir.glob("*.yaml"))
    assert len(yaml_files) == 25, (
        f"Expected 25 eval case YAML files, got {len(yaml_files)}: {[f.name for f in yaml_files]}"
    )
    # G1 + G2 test modules exist and are syntactically valid Python.
    tests_dir = _SRC_ROOT.parent.parent / "tests"
    for name in ("test_g1_eval_cases.py", "test_g2_eval_cases.py"):
        test_file = tests_dir / name
        assert test_file.is_file(), f"eval cases test file missing: {test_file}"
        compile(test_file.read_text(encoding="utf-8"), str(test_file), "exec")
