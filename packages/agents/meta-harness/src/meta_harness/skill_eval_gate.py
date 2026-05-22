"""Skill eval-gate — Task 8 of A.4 v0.2.

The **mandatory** gate every ``SkillCandidate`` clears before A.4 will
deploy it to a target agent's NLAH skills directory. Per Q4 of the
v0.2 plan and the operator's safety directive: **no ``--force`` flag,
no CLI bypass, no eval-gate-skipped path.**

Implements **Option B** from Q4 — two eval runs per candidate, no KG
dependency:

1. **Baseline run** — execute the target agent's eval suite **without**
   the candidate skill loaded; capture per-case results.
2. **With-candidate run** — execute the same suite with the candidate
   exposed via the ``with_candidate_skill_overlay`` context manager;
   capture per-case results.

Gate verdict requires BOTH conditions:

* **Per-case** — no individual case may drop by ≥5 percentage points
  (``PER_CASE_REGRESSION_THRESHOLD_PCT``). For binary eval cases the
  only regression value is a passed→failed flip (100-point drop) —
  any such flip fails the gate.
* **Overall** — aggregate ``candidate_pass_rate`` must be ≥
  ``baseline_pass_rate`` (no aggregate regression).

The result is cached at
``<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/eval_gate_result.json``
so Task 13's driver can read the verdict without re-running.

**Overlay binding via ``contextvars.ContextVar``** rather than module-
level monkeypatching (the ``nlah_override`` pattern Task 5 / v0.1
uses) — ContextVar is async-safe and supports nested overlays, so
the eval-gate doesn't race with concurrent A.4 work. Agents that have
migrated to v0.2-aware skill loading consult ``get_active_skill_overlay``
and pass the result to ``charter.nlah_loader.load_skill_metadata_index(
skills_overlay=...)``. v0.1 agents (those that don't yet read the
overlay) are unaffected — their candidate-run pass-rate equals their
baseline, gate trivially passes, no false-positive regressions.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.results import SuiteResult
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite

from meta_harness.schemas import EvalGateResult, SkillCandidate

#: Per-case regression threshold in percentage points. A case-level
#: drop at or above this value fails the gate even if the overall
#: pass-rate improved.
PER_CASE_REGRESSION_THRESHOLD_PCT = 5.0

#: ContextVar that exposes the active candidate-skill overlay path to
#: any code in the call tree that asks. Async-safe (each Task has its
#: own copy); nested overlays restore correctly on exit.
_active_skill_overlay: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "meta_harness.skill_eval_gate.active_skill_overlay",
    default=None,
)


class SkillEvalGateError(RuntimeError):
    """Raised when the eval-gate cannot be evaluated — empty case set,
    missing target-agent runner, malformed cached result, etc."""


@contextmanager
def with_candidate_skill_overlay(overlay_dir: Path | str) -> Iterator[None]:
    """Expose ``overlay_dir`` to skill-loading code in the call tree.

    Thin wrapper over the ContextVar binding. Conceptually mirrors v0.1's
    ``nlah_override`` (which monkeypatched ``charter.nlah_loader.default_nlah_dir``)
    but uses ``contextvars`` so concurrent eval runs don't race.

    The overlay dir is the per-agent shadow root
    ``<workspace>/.nexus/candidate-skills/<agent_id>/`` — its contents
    follow the same ``<category>/<skill-name>/SKILL.md`` shape as the
    bundled ``nlah/skills/`` tree, so the path can be passed verbatim
    to ``charter.nlah_loader.load_skill_metadata_index(skills_overlay=...)``.
    """
    token = _active_skill_overlay.set(Path(overlay_dir))
    try:
        yield
    finally:
        _active_skill_overlay.reset(token)


def get_active_skill_overlay() -> Path | None:
    """Return the currently-active candidate-skill overlay, or ``None``.

    Agents that have migrated to v0.2-aware NLAH loading call this and
    pass the result as
    ``charter.nlah_loader.load_skill_metadata_index(skills_overlay=...)``.
    Outside an active ``with_candidate_skill_overlay`` block this is
    ``None`` and agents fall back to bundled-skill-only mode.
    """
    return _active_skill_overlay.get()


def compute_per_agent_overlay_dir(
    *,
    workspace_root: Path | str,
    agent_id: str,
) -> Path:
    """Per-agent overlay root used by the eval-gate.

    Returns ``<workspace>/.nexus/candidate-skills/<agent_id>/``. Skills
    beneath it live at ``<category>/<skill-name>/SKILL.md`` — the same
    layout as the bundled ``nlah/skills/`` tree, so the path is a
    drop-in argument for
    ``charter.nlah_loader.load_skill_metadata_index(skills_overlay=...)``.
    """
    return Path(workspace_root) / ".nexus" / "candidate-skills" / agent_id


def compute_eval_gate_result_path(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Cache path for one candidate's eval-gate verdict.

    Sits alongside the candidate's SKILL.md so Task 10 (approval) and
    Task 13 (driver) can find both together:

    ``<workspace>/.nexus/candidate-skills/<agent_id>/<skill_id>/eval_gate_result.json``
    """
    return (
        Path(workspace_root)
        / ".nexus"
        / "candidate-skills"
        / agent_id
        / skill_id
        / "eval_gate_result.json"
    )


def compute_per_case_regressions(
    baseline: SuiteResult,
    candidate: SuiteResult,
) -> tuple[tuple[str, float], ...]:
    """Return ``(case_id, drop_pct)`` for every case that regressed.

    Reports cases where the candidate run did **worse** than baseline.
    Improvements (failed→passed) and no-change cases (both passed or
    both failed) are NOT included. For binary eval cases the only
    regression value is a 100-point drop (passed→failed flip).

    Missing-from-candidate cases that passed in the baseline are
    treated as full regressions (drop=100.0) — the candidate run
    couldn't reproduce them.

    Entries are sorted by ``case_id`` so the tuple is deterministic.
    """
    baseline_by_id = {c.case_id: c for c in baseline.cases}
    candidate_by_id = {c.case_id: c for c in candidate.cases}
    regressions: list[tuple[str, float]] = []
    for case_id in sorted(baseline_by_id.keys()):
        baseline_case = baseline_by_id[case_id]
        candidate_case = candidate_by_id.get(case_id)
        if candidate_case is None:
            if baseline_case.passed:
                regressions.append((case_id, 100.0))
            continue
        if baseline_case.passed and not candidate_case.passed:
            regressions.append((case_id, 100.0))
    return tuple(regressions)


def evaluate_gate(
    *,
    baseline_pass_rate: float,
    candidate_pass_rate: float,
    per_case_regressions: tuple[tuple[str, float], ...],
) -> bool:
    """Verdict: gate passes only when BOTH conditions hold.

    1. Aggregate ``candidate_pass_rate`` ≥ ``baseline_pass_rate``.
    2. No individual case dropped by ≥ ``PER_CASE_REGRESSION_THRESHOLD_PCT``
       (5 percentage points).
    """
    if candidate_pass_rate < baseline_pass_rate:
        return False
    for _case_id, drop_pct in per_case_regressions:
        if drop_pct >= PER_CASE_REGRESSION_THRESHOLD_PCT:
            return False
    return True


def cache_eval_gate_result(
    result: EvalGateResult,
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Write ``result`` to the cache path; return the path."""
    path = compute_eval_gate_result_path(
        workspace_root=workspace_root,
        agent_id=agent_id,
        skill_id=skill_id,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_cached_eval_gate_result(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> EvalGateResult | None:
    """Return the cached verdict, or ``None`` when no cache file exists."""
    path = compute_eval_gate_result_path(
        workspace_root=workspace_root,
        agent_id=agent_id,
        skill_id=skill_id,
    )
    if not path.is_file():
        return None
    return EvalGateResult.model_validate_json(path.read_text(encoding="utf-8"))


async def run_skill_eval_gate(
    *,
    candidate: SkillCandidate,
    workspace_root: Path | str,
    cases: list[EvalCase],
    runner: EvalRunner,
    llm_provider: LLMProvider | None = None,
    evaluated_at: datetime | None = None,
) -> EvalGateResult:
    """Run the Option-B eval gate and return a populated ``EvalGateResult``.

    Two runs of ``cases`` through ``runner``:

    * Baseline — no overlay active.
    * With-candidate — ``with_candidate_skill_overlay`` exposes the
      per-agent shadow dir (computed from ``workspace_root`` +
      ``candidate.skill.target_agent``).

    The result is **not** automatically cached — the caller (Task 13
    driver) decides when to persist via ``cache_eval_gate_result``,
    typically immediately after evaluation succeeds.

    Raises:
        SkillEvalGateError: when ``cases`` is empty (gate needs cases
        to compare — vacuous results are not safely interpretable).
    """
    if not cases:
        raise SkillEvalGateError(
            f"skill_id={candidate.skill_id!r}: eval-gate requires non-empty cases "
            f"(target_agent={candidate.skill.target_agent!r})"
        )

    baseline = await run_suite(cases, runner, llm_provider=llm_provider)

    overlay_dir = compute_per_agent_overlay_dir(
        workspace_root=workspace_root,
        agent_id=candidate.skill.target_agent,
    )
    with with_candidate_skill_overlay(overlay_dir):
        with_candidate = await run_suite(cases, runner, llm_provider=llm_provider)

    per_case_regressions = compute_per_case_regressions(baseline, with_candidate)
    gate_passed = evaluate_gate(
        baseline_pass_rate=baseline.pass_rate,
        candidate_pass_rate=with_candidate.pass_rate,
        per_case_regressions=per_case_regressions,
    )
    return EvalGateResult(
        skill_id=candidate.skill_id,
        target_agent=candidate.skill.target_agent,
        baseline_pass_rate=baseline.pass_rate,
        candidate_pass_rate=with_candidate.pass_rate,
        per_case_regressions=per_case_regressions,
        passed=gate_passed,
        evaluated_at=evaluated_at if evaluated_at is not None else datetime.now(UTC),
    )


__all__ = [
    "PER_CASE_REGRESSION_THRESHOLD_PCT",
    "SkillEvalGateError",
    "cache_eval_gate_result",
    "compute_eval_gate_result_path",
    "compute_per_agent_overlay_dir",
    "compute_per_case_regressions",
    "evaluate_gate",
    "get_active_skill_overlay",
    "load_cached_eval_gate_result",
    "run_skill_eval_gate",
    "with_candidate_skill_overlay",
]
