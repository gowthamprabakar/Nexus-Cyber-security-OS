"""Smoke tests — meta_harness package imports + Q-ARCH deferral guards.

Task 1 (Bootstrap). 12 tests:

1.  Package version (``__version__`` wired).
2.  ADR-007 v1.2 — ``charter.nlah_loader`` reachable (A.4 reads
    every agent's NLAH dir via the loader contract).
3.  ADR-008 — ``eval_framework`` reachable (A.4 directly consumes
    ``cases.load_cases`` / ``runner.EvalRunner`` Protocol /
    ``suite.run_suite`` / ``nexus_eval_runners`` entry-point group).
4.  ADR-007 v1.1 — ``charter.llm_adapter`` reachable (A.4's own
    meta-eval cases may use LLM stubs).
5.  D.13 Synthesis ``_scan_classifier_labels`` importable (Q6
    invariant reuse if A.4 self-eval needs guard).
6.  Anti-pattern guard — no per-agent ``meta_harness.llm`` module.
7.  Entry-point — ``meta_harness`` eval-runner registered.
8.  Entry-point — ``meta-harness`` console script registered.
9.  **Q-ARCH-1 guard** — no ``claims_subject`` / ``CLAIMS_STREAM``
    import in any ``meta_harness`` source file. v0.1 is read-only;
    v0.2 plan MUST review subscriber-ACL per ADR-012 before
    re-introducing.
10. **Q-ARCH-2 guard** — no new fabric subject literal (``meta.``
    or ``proposals.``) anywhere under src/. v0.2 may introduce one;
    v0.1 ships workspace markdown + KG only.
11. **Q-ARCH-3 / WI-4 guard** — no write-mode file open and no
    ``Path.write_*`` invocation under any ``nlah/`` path. NLAH
    access is strictly read-only in v0.1.
12. WI-1 substrate guard — no source file under ``packages/charter/``
    or ``packages/shared/`` is modified by A.4 source. Bootstrap
    probes the **absence** of any direct imports that would imply
    a substrate write.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "meta_harness"


def _iter_source_files() -> list[Path]:
    return sorted(p for p in _SRC_ROOT.rglob("*.py") if p.is_file())


def test_package_imports() -> None:
    import meta_harness

    assert hasattr(meta_harness, "__version__")
    assert isinstance(meta_harness.__version__, str)
    # Phase 1 / Wave 0 — v0.2 ships autonomous skill creation +
    # progressive-disclosure NLAH loader + auto-deploy safety rails.
    assert meta_harness.__version__ == "0.2.5"


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — A.4 is the **twelfth** agent shipped natively
    against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture /
    k8s-posture / D.5 / D.8 / D.6 / D.13 / D.12)."""
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_eval_framework_import_works() -> None:
    """ADR-008 — A.4 directly consumes the eval-framework primitives."""
    from eval_framework.cases import load_cases  # noqa: F401
    from eval_framework.runner import EvalRunner  # noqa: F401
    from eval_framework.suite import run_suite  # noqa: F401


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — A.4's own meta-eval cases may use LLM stubs."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_synthesis_reviewer_import_works() -> None:
    """Q6 invariant — D.13's classifier-substring guard remains
    available for any A.4 meta-eval case that needs it."""
    from synthesis.reviewer import _scan_classifier_labels  # noqa: F401


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — A.4 must NOT ship a local
    ``llm.py``. Always go through ``charter.llm_adapter``."""
    import importlib.util

    assert importlib.util.find_spec("meta_harness.llm") is None, (
        "meta_harness must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``meta_harness = meta_harness.eval_runner:MetaHarnessEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 12."""
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "meta_harness" in names, f"meta_harness eval-runner not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``meta-harness = meta_harness.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 13."""
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "meta-harness" in names, f"meta-harness console script not registered; got {names}"


# ---------------------------------------------------------------------------
# Q-ARCH deferral guards — these scan the package source tree and assert
# that no v0.2+ surface area sneaks into v0.1.
# ---------------------------------------------------------------------------


def test_qarch1_no_claims_publish_surface() -> None:
    """Q-ARCH-1 deferral — A.4 v0.1 has no ``claims.>`` publish
    capability. The fence here is a source-grep: no source file
    imports ``claims_subject`` or ``CLAIMS_STREAM`` from
    ``shared.fabric``. If A.4 v0.2 introduces auto-acting behavior,
    the v0.2 plan MUST review subscriber-ACL per ADR-012 (WI-5
    carry-forward).
    """
    forbidden = ("claims_subject", "CLAIMS_STREAM")
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append((path, token))
    assert not offenders, (
        "Q-ARCH-1 violation — A.4 v0.1 must not import claims.> publish surface. "
        f"Offenders: {offenders}"
    )


def test_qarch2_no_new_fabric_subject_literal() -> None:
    """Q-ARCH-2 deferral — no ``meta.`` or ``proposals.`` subject
    literal anywhere under src/. v0.2 may introduce one (modeled
    on ADR-012's shape); v0.1 ships workspace markdown + KG only.
    """
    forbidden_prefixes = ("meta.tenant.", "proposals.tenant.", "proposals.>", "meta.>")
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        for token in forbidden_prefixes:
            if token in text:
                offenders.append((path, token))
    assert not offenders, (
        "Q-ARCH-2 violation — A.4 v0.1 must not declare a new fabric subject. "
        f"Offenders: {offenders}"
    )


def test_qarch3_wi4_readme_documents_read_only_nlah_access() -> None:
    """Q-ARCH-3 / WI-4 — A.4 is strictly read-only against the NLAH
    directories of other agents. The **runtime** guard (file-open
    interception under any ``packages/agents/*/src/*/nlah/`` glob)
    ships in Task 3's ``nlah_parser`` integration test. At
    bootstrap stage we anchor the commitment in the README so any
    future developer reading the package start-page sees the
    deferral verbatim before touching tools/nlah_parser.py.
    """
    readme = (_SRC_ROOT.parent.parent / "README.md").read_text(encoding="utf-8")
    assert "read-only" in readme.lower(), "README must document read-only commitment"
    assert "NLAH writes" in readme or "NLAH auto-deploy" in readme, (
        "README must name the NLAH-write deferral verbatim"
    )


def test_wi1_substrate_sealed_substrate_imports_reachable() -> None:
    """WI-1 — substrate sealed. Bootstrap-stage probe: the
    consumer-side surface A.4 will use in Task 8 (SemanticStore
    upsert/list helpers) imports cleanly. A.4 v0.1 makes **zero**
    changes to ``packages/charter/`` or ``packages/shared/``; the
    diff-empty check is verified at close (Task 16 verification
    record). This positive-control probe confirms the consumer
    surface exists.
    """
    from charter.memory.semantic import SemanticStore  # noqa: F401


# ---------------------------------------------------------------------------
# v0.2 invariants
# ---------------------------------------------------------------------------


def test_v0_2_pyproject_version_matches() -> None:
    """Bootstrap regression — the pyproject.toml + ``__version__``
    must agree."""
    import tomllib

    import meta_harness

    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    pyproject_version = data["project"]["version"]
    assert pyproject_version == meta_harness.__version__, (
        f"pyproject.toml {pyproject_version} != __version__ {meta_harness.__version__}"
    )


def test_v0_2_charter_llm_adapter_now_permitted_for_skill_create() -> None:
    """v0.2 introduces LLM consumption at Stage 7 SKILL_CREATE.
    ``charter.llm_adapter`` must be reachable; the v0.1 anti-pattern
    guard (no per-agent ``meta_harness.llm`` module) still holds."""
    import importlib.util

    from charter.llm_adapter import config_from_env, make_provider  # noqa: F401

    # Per-agent llm.py anti-pattern guard still holds in v0.2 —
    # A.4 consumes the LLM via charter.llm_adapter, not a local
    # module.
    assert importlib.util.find_spec("meta_harness.llm") is None


@pytest.mark.asyncio
async def test_v0_2_backwards_compat_empty_skills_v0_1_equivalent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**WI-4 backwards-compat regression probe — LOAD-BEARING per
    plan drift #5.** Running ``meta_harness.agent.run`` against an
    empty skills/ directory (Task 1 ships nothing skill-related
    yet) + zero novel-pattern runs MUST produce a
    ``MetaHarnessReport`` structurally equivalent to v0.1 output.
    Fields that legitimately vary (timestamps, ULIDs) are not
    compared; the shape + counts must be identical.

    Task 1 ships the version bump only; no skills code lives in
    the repo yet. This probe asserts that no skills-related
    side-effects sneak in via the version bump alone. Tasks 5-13
    introduce the skill subsystem; this same probe re-runs after
    each task to catch regressions.
    """
    from meta_harness import agent as agent_mod
    from meta_harness.eval import batch as batch_module

    # Empty entry-point set -> v0.1 happy-path with zero work.
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    report = await agent_mod.run(
        customer_id="acme",
        run_id="r_v0_2_bootstrap_compat_probe",
        workspace_root=tmp_path,
    )

    # v0.1-equivalent expectations: empty inputs -> empty outputs.
    assert report.total_agents_evaluated == 0
    assert report.successful_runs == 0
    assert report.total_regressions == 0
    assert report.ab_comparison is None
    assert report.scorecards == ()
    assert report.scorecard_deltas == ()
    assert report.manifests == ()
    # Report markdown written to workspace (v0.1 behavior).
    assert (tmp_path / "meta_harness_report.md").is_file()


def test_v0_2_progressive_disclosure_skills_dir_convention() -> None:
    """Bootstrap-stage probe — the v0.2 skills/ subdirectory
    convention is established but not yet populated (Tasks 4 + 5
    add the loader + discovery; Task 1 just version-bumps).

    Future agents' NLAH directories will gain a ``skills/`` sibling
    under their existing ``nlah/`` directory:

        packages/agents/<agent>/src/<agent>/nlah/skills/

    Per ADR-007 v1.4 (lands paired with Task 4). At Task 1 stage,
    the convention is a documented intent; the probe asserts the
    plan doc names it verbatim so a future regression that drops
    the convention is caught at the next smoke run.
    """
    plan_path = (
        Path(__file__).resolve().parents[4]
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-05-22-a-4-meta-harness-v0-2.md"
    )
    plan_text = plan_path.read_text(encoding="utf-8")
    # The conventional path must appear verbatim in the plan.
    assert "nlah/skills/" in plan_text
    # ADR-007 v1.4 must be named in the plan (v1.3 was already taken
    # by the 2026-05-12 always-on agent class amendment).
    assert "ADR-007 v1.4" in plan_text
    # The plan must explicitly flag the reassignment from the
    # previously-flagged v1.4 candidate slot.
    assert "v1.3 was already taken" in plan_text


def test_v0_2_q_arch_5_trajectory_closes_at_three_subscribers() -> None:
    """**WI-5 closure probe.** Plan doc must record that A.4 v0.2's
    forbidden-subscriber registration closes the Q-ARCH-1 trajectory
    at THREE forbidden subscribers (A.1 + Supervisor + A.4 v0.2)
    with no further pending additions in Phase 1."""
    plan_path = (
        Path(__file__).resolve().parents[4]
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-05-22-a-4-meta-harness-v0-2.md"
    )
    plan_text = plan_path.read_text(encoding="utf-8")
    assert "Q-ARCH-1 trajectory CLOSES" in plan_text
    # The plan records "3 forbidden subscribers" in the WI-5 closure
    # section (digit form), naming A.1 + Supervisor + A.4 v0.2 as
    # the final v0.2 set.
    assert "3 forbidden subscribers" in plan_text
    assert "no further pending additions" in plan_text.lower()
