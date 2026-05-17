"""Tests for `investigation.eval_runner.InvestigationEvalRunner` (D.7 Task 14).

Production contract:

- Conforms to `eval_framework.runner.EvalRunner` Protocol.
- `agent_name == "investigation"` matches the pyproject entry-point.
- Registered via `nexus_eval_runners` entry-point.
- Interprets the F.6/F.5-style YAML fixture schema from Task 13.
- All 10 shipped YAML cases pass — the **10/10 acceptance gate**.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from investigation.eval_runner import InvestigationEvalRunner

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(case_file: Path) -> EvalCase:
    raw = yaml.safe_load(case_file.read_text())
    return EvalCase(
        case_id=raw["case_id"],
        description=raw.get("description", ""),
        fixture=raw.get("fixture") or {},
        expected=raw.get("expected") or {},
    )


# ---------------------------- protocol + name ---------------------------


def test_investigation_eval_runner_is_an_eval_runner() -> None:
    runner = InvestigationEvalRunner()
    assert isinstance(runner, EvalRunner)


def test_runner_agent_name_matches_entry_point() -> None:
    assert InvestigationEvalRunner().agent_name == "investigation"


def test_entry_point_resolves_to_runner() -> None:
    from importlib.metadata import entry_points

    eps = entry_points(group="nexus_eval_runners")
    ep = next(e for e in eps if e.name == "investigation")
    assert ep.load() is InvestigationEvalRunner


# ---------------------------- per-case execution ------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_filename",
    [
        "001_empty_corpus.yaml",
        "002_audit_only_no_hypotheses.yaml",
        "003_single_finding_fallback.yaml",
        "004_cross_agent_merge.yaml",
        "005_ioc_extraction.yaml",
        "006_mitre_attribution.yaml",
        "007_llm_hypothesis_validated.yaml",
        "008_llm_hallucination_dropped.yaml",
        "009_time_window_filter.yaml",
        "010_containment_plan_per_class.yaml",
    ],
)
async def test_each_shipped_case_passes(tmp_path: Path, case_filename: str) -> None:
    case = _load_case(_CASES_DIR / case_filename)
    passed, reason, _, _ = await InvestigationEvalRunner().run(
        case, workspace=tmp_path / case.case_id
    )
    assert passed, f"{case.case_id}: {reason}"


# ---------------------------- full 10/10 acceptance ---------------------


@pytest.mark.asyncio
async def test_all_10_shipped_cases_pass(tmp_path: Path) -> None:
    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10, f"D.7 ships exactly 10 eval cases; got {len(case_files)}"

    runner = InvestigationEvalRunner()
    failures: list[str] = []
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, _, _ = await runner.run(case, workspace=tmp_path / case.case_id)
        if not passed:
            failures.append(f"{case.case_id}: {reason}")
    assert not failures, "\n".join(failures)


# ---------------------------- audit log emission ------------------------


@pytest.mark.asyncio
async def test_runner_emits_audit_log_path(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "003_single_finding_fallback.yaml")
    _, _, _, audit_log_path = await InvestigationEvalRunner().run(case, workspace=tmp_path)
    assert audit_log_path is not None
    assert audit_log_path.is_file()


# ============================================================================
# F.7 v0.2 Task 6 — both-modes eval gate (CLOSES watch-item 2)
#
# Plan row 6 requires 10/10 D.7 eval cases pass with the flag OFF AND with
# the flag ON. The OFF half was already proven at Task 3 (CLI eval + an
# agent-level test). This block closes the ON half: every shipped eval
# case must pass with publish_events_to_bus=True, AND the actuals must be
# byte-identical to the OFF run. That is the **additive-only proof**:
# turning the bus on changes D.7's investigation outcomes by exactly zero.
#
# NO production code change. The flag is injected by monkeypatching
# `investigation.eval_runner.investigation_run` at the test boundary
# (a closure that adds `publish_events_to_bus=True` to kwargs before
# delegating to the real `investigation.agent.run`). The BusEmitter's
# underlying JetStreamClient is also monkeypatched to a no-broker
# stand-in so no NATS server is required.
# ============================================================================


class _NoBrokerJetStreamClient:
    """Test double for the JetStreamClient used inside BusEmitter when the
    eval-gate exercises the flag-ON path. Every method succeeds without
    touching a real broker. This lets the REAL bus_emit code path run
    end-to-end — recording bus_publish.attempt + .success entries to the
    audit chain — but without requiring a NATS server. The eval cases'
    `actuals` are IncidentReport properties only, so the additional
    audit entries do not affect pass/fail.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.connect = AsyncMock()
        self.close = AsyncMock()
        self.ensure_streams = AsyncMock()
        # PubAck-shaped return so bus_emit.success entries get realistic
        # stream + seq payload fields.
        self.publish = AsyncMock(return_value=MagicMock(stream="events", seq=1))


def _patch_for_flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire the test-side injection: flag=True forwarded into agent.run
    inside the eval runner, with the BusEmitter's JetStreamClient
    replaced by a no-broker stand-in."""
    import investigation.bus_emit as bus_emit_mod
    import investigation.eval_runner as runner_mod

    monkeypatch.setattr(bus_emit_mod, "JetStreamClient", _NoBrokerJetStreamClient)

    original = runner_mod.investigation_run

    async def _flag_on_run(*args: object, **kwargs: object) -> object:
        kwargs["publish_events_to_bus"] = True
        return await original(*args, **kwargs)

    monkeypatch.setattr(runner_mod, "investigation_run", _flag_on_run)


@pytest.mark.asyncio
async def test_eval_suite_passes_10_of_10_with_flag_off(tmp_path: Path) -> None:
    """Re-pin: 10/10 with flag OFF (back-compat — already proven at Task 3).

    Re-runs the full suite here so both modes' results land in one
    test file for the verification record's eval-gate citation.
    """
    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10, f"D.7 ships exactly 10 eval cases; got {len(case_files)}"

    runner = InvestigationEvalRunner()
    failures: list[str] = []
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, _, _ = await runner.run(case, workspace=tmp_path / f"off-{case.case_id}")
        if not passed:
            failures.append(f"{case.case_id}: {reason}")
    assert not failures, "FLAG-OFF failures:\n" + "\n".join(failures)


@pytest.mark.asyncio
async def test_eval_suite_passes_10_of_10_with_flag_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LOAD-BEARING — the additive-only proof (F.7 v0.2 plan row 6,
    closes watch-item 2's flag-ON half).

    Every D.7 eval case must pass with `publish_events_to_bus=True`.
    Outcomes are part of D.7's behavioural contract; if any case fails
    in flag-ON mode, the migration is not additive and the plan rejects.

    NO production code modified — the flag is injected by monkeypatching
    `investigation.eval_runner.investigation_run` (the eval runner's
    handle to agent.run) so each case runs with flag=True. The
    BusEmitter's underlying JetStreamClient is a no-broker test double.
    """
    _patch_for_flag_on(monkeypatch)

    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10

    runner = InvestigationEvalRunner()
    failures: list[str] = []
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, _, _ = await runner.run(case, workspace=tmp_path / f"on-{case.case_id}")
        if not passed:
            failures.append(f"{case.case_id}: {reason}")
    assert not failures, "FLAG-ON failures:\n" + "\n".join(failures)


@pytest.mark.asyncio
async def test_eval_actuals_byte_identical_between_flag_off_and_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The additive-only contract written as an executable assertion.

    For every shipped eval case: capture `actuals` (hypotheses_count /
    timeline_events_count / has_iocs / ioc_count / has_mitre_techniques /
    ocsf_class_uid) with flag OFF; capture again with flag ON; assert
    the two dicts are EQUAL.

    This is the strongest form of the watch-item 2 closure: not just
    "both modes pass the eval bar" but "both modes produce identical
    investigation outcomes". The bus path adds only a side-effect, not
    a perturbation of D.7's pipeline.
    """
    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10

    # Flag OFF — baseline outcomes.
    runner = InvestigationEvalRunner()
    actuals_off: dict[str, dict[str, object]] = {}
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, actuals, _ = await runner.run(
            case, workspace=tmp_path / f"off-{case.case_id}"
        )
        assert passed, f"flag OFF {case.case_id}: {reason}"
        actuals_off[case.case_id] = dict(actuals)

    # Flag ON — same suite, monkeypatched flag injection.
    _patch_for_flag_on(monkeypatch)
    actuals_on: dict[str, dict[str, object]] = {}
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, actuals, _ = await runner.run(
            case, workspace=tmp_path / f"on-{case.case_id}"
        )
        assert passed, f"flag ON {case.case_id}: {reason}"
        actuals_on[case.case_id] = dict(actuals)

    # Byte-identical actuals across both modes. Per-case diff on
    # mismatch so the error message names exactly which case + which
    # field changed (instead of a giant dict-equality blob).
    mismatches: list[str] = []
    for case_id in actuals_off:
        off = actuals_off[case_id]
        on = actuals_on[case_id]
        if off != on:
            diff = {
                k: (off.get(k), on.get(k)) for k in set(off) | set(on) if off.get(k) != on.get(k)
            }
            mismatches.append(f"{case_id}: {diff}")
    assert not mismatches, (
        "FLAG OFF ↔ FLAG ON actuals diverge (additive-only proof FAILED):\n" + "\n".join(mismatches)
    )
