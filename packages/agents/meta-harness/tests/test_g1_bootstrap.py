"""G1 bootstrap smoke tests — Task 1 (version bump + regression gates).

10 tests:

1.  G1 version is 0.2.2 (``meta_harness.__version__``).
2.  G1 pyproject version matches ``__version__`` (reads from source file).
3.  Existing v0.2 modules import cleanly after version bump.
4.  G1 plan doc exists at the expected path and names key conventions.
5.  **WI-1 / substrate seal** — no substrate-file path manipulation in
    meta_harness source.
6.  **Safety gate 1 (novelty)** — ``detect_skill_trigger`` importable;
    ``compute_tool_sequence_hash`` deterministic.
7.  **Safety gate 2 (trust-boundary)** — ``_FORBIDDEN_SUBSCRIPTIONS``
    still contains ``meta_harness`` entry.
8.  **Safety gate 3 (eval-gate)** — ``run_skill_eval_gate`` +
    ``with_candidate_skill_overlay`` importable; no ``--force`` in CLI.
9.  **Safety gate 4 (class-registry)** — ``SkillClassRegistry`` importable.
10. **Safety gate 5 (routing enforcement)** — ``_promote_to_canonical``,
    ``reject_candidate``, ``write_candidate_notification`` importable.
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


def test_g1_version_is_0_2_1() -> None:
    """Bootstrap gate — ``__version__`` wired to 0.2.2 (G1 cycle)."""
    import meta_harness

    assert hasattr(meta_harness, "__version__")
    assert isinstance(meta_harness.__version__, str)
    assert meta_harness.__version__ == "0.2.5", (
        f"Expected 0.2.5 (live; G1 shipped 0.2.2), got {meta_harness.__version__}"
    )


def test_g1_pyproject_version_matches() -> None:
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


def test_g1_existing_v0_2_modules_import_cleanly() -> None:
    """All v0.2 modules still import after version bump."""
    from meta_harness import (
        audit_emit,  # noqa: F401
        schemas,  # noqa: F401
        skill_approval,  # noqa: F401
        skill_discovery,  # noqa: F401
        skill_eval_gate,  # noqa: F401
        skill_format,  # noqa: F401
        skill_lifecycle,  # noqa: F401
        skill_registry,  # noqa: F401
        skill_triggers,  # noqa: F401
        skill_writer,  # noqa: F401
    )


def test_g1_cli_and_eval_entry_points_still_registered() -> None:
    """v0.2 entry-points still registered after version bump."""
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


def test_g1_plan_doc_exists_and_names_scope() -> None:
    """G1 plan doc must exist at the expected path and name key conventions."""
    plan_path = (
        _REPO_ROOT / "docs" / "superpowers" / "plans" / "2026-05-24-g1-effectiveness-scoring.md"
    )
    assert plan_path.is_file(), f"G1 plan doc not found at {plan_path}"
    plan_text = plan_path.read_text(encoding="utf-8")
    # G1 scope signals
    assert "effectiveness scoring" in plan_text.lower()
    assert "0-1" in plan_text  # composite score range
    assert "GEPA" in plan_text  # v0.2.5 consumer
    assert "sidecar" in plan_text.lower()  # storage pattern
    # G1 key naming conventions
    assert "effectiveness.json" in plan_text
    assert "run-events.jsonl" in plan_text
    # Task count
    assert "16 tasks" in plan_text.lower() or "16/16" in plan_text.lower()


# ---------------------------------------------------------------------------
# WI-1 — substrate sealed
# ---------------------------------------------------------------------------


def test_g1_wi1_no_substrate_path_manipulation() -> None:
    """WI-1 — meta_harness source must not reference charter/ or shared/
    source paths for write operations. Task 3 (audit vocab) is the only
    planned substrate touch and has not landed yet."""
    forbidden_patterns = [
        "packages/charter/",
        "packages/shared/",
    ]

    offenders: list[str] = []
    for src_path in _iter_source_files():
        text = src_path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            if pattern in text:
                offenders.append(
                    f"{src_path.relative_to(_SRC_ROOT.parent.parent)}: contains {pattern!r}"
                )

    # Offenders are acceptable only if they're in tests or are import-only
    # references (not file-system writes). For bootstrap, zero offenders
    # is the expectation — no G1 code touches substrate yet.
    # If existing v0.2 modules reference shared/charter for imports, that's
    # expected (they import from those packages). The gate is on NEW
    # substrate-touching code. At bootstrap, no new modules exist.
    assert not offenders, (
        "WI-1 violation — meta_harness source should not reference substrate paths. "
        f"Offenders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Safety gate 1 — novelty (Q3 trigger: hash-novel tool sequence)
# ---------------------------------------------------------------------------


def test_g1_safety_gate_1_novelty_trigger_intact() -> None:
    """Safety gate 1 — 3-condition trigger gate still importable and
    functional shape intact (>=5 tool calls, successful, hash-novel)."""
    from meta_harness.skill_triggers import compute_tool_sequence_hash

    # Hash of known input is deterministic.
    h1 = compute_tool_sequence_hash(["tool_a", "tool_b", "tool_c"])
    h2 = compute_tool_sequence_hash(["tool_a", "tool_b", "tool_c"])
    assert h1 == h2
    assert isinstance(h1, str) and len(h1) == 64  # SHA-256


# ---------------------------------------------------------------------------
# Safety gate 2 — trust-boundary (Q-ARCH-1: _FORBIDDEN_SUBSCRIPTIONS)
# ---------------------------------------------------------------------------


def test_g1_safety_gate_2_forbidden_subscriptions_holds() -> None:
    """Safety gate 2 — meta_harness still in _FORBIDDEN_SUBSCRIPTIONS."""
    from shared.fabric.client import _FORBIDDEN_SUBSCRIPTIONS

    assert "meta_harness" in _FORBIDDEN_SUBSCRIPTIONS, (
        "Q-ARCH-1 violation — meta_harness must remain forbidden subscriber"
    )
    assert _FORBIDDEN_SUBSCRIPTIONS["meta_harness"] == frozenset({"claims.>"})


# ---------------------------------------------------------------------------
# Safety gate 3 — eval-gate mandatory, no --force
# ---------------------------------------------------------------------------


def test_g1_safety_gate_3_no_force_flag_in_cli() -> None:
    """Safety gate 3 — CLI source must not contain a --force flag that
    bypasses eval-gate (CF #3 triple-gate discipline)."""
    cli_path = _SRC_ROOT / "cli.py"
    assert cli_path.is_file()
    cli_text = cli_path.read_text(encoding="utf-8")

    # --force must not appear as a CLI option
    assert "--force" not in cli_text, (
        "Safety gate 3 violation — --force flag found in CLI. "
        "Eval-gate bypass is prohibited per Q4 + Task 8 + Task 14 triple-gate."
    )


def test_g1_safety_gate_3_eval_gate_module_intact() -> None:
    """Safety gate 3 — eval-gate module importable; Option-B two-run
    comparison + regression threshold accessible."""
    from meta_harness.skill_eval_gate import (  # noqa: F401
        run_skill_eval_gate,
        with_candidate_skill_overlay,
    )


# ---------------------------------------------------------------------------
# Safety gate 4 — class-registry (first-of-class operator approval)
# ---------------------------------------------------------------------------


def test_g1_safety_gate_4_class_registry_intact() -> None:
    """Safety gate 4 — skill-class registry importable; first-of-class
    gate still in place."""
    from meta_harness.skill_registry import SkillClassRegistry  # noqa: F401


# ---------------------------------------------------------------------------
# Safety gate 5 — routing enforcement (eval-gate → registry → deploy or queue)
# ---------------------------------------------------------------------------


def test_g1_safety_gate_5_routing_paths_intact() -> None:
    """Safety gate 5 — all three routing paths importable: promote
    (auto-deploy), reject, and notification (pending review)."""
    from meta_harness.skill_approval import (  # noqa: F401
        _promote_to_canonical,
        reject_candidate,
        write_candidate_notification,
    )
