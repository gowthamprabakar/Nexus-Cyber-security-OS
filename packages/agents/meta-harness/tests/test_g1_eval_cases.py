"""G1 effectiveness-scoring eval cases — Task 15.

Reads the 5 YAML case files (16-20) from ``eval/cases/`` and executes
them against the real G1 Python modules.  Each case seeds sidecar data
(``run-events.jsonl`` and/or ``operator-ratings.jsonl``), calls the
appropriate G1 function, and asserts on the expected shape documented
in the YAML.

G1 scoring is pure arithmetic — no LLM, no MetaHarnessEvalRunner.
These tests verify end-to-end correctness of the composite scoring
pipeline: adoption, outcome, feedback, backwards-compat, idempotency,
and API shape.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from charter.audit import AuditLog
from meta_harness.effectiveness_compat import apply_backwards_compat_reason
from meta_harness.effectiveness_store import (
    get_effectiveness_score,
    write_effectiveness_score,
)
from meta_harness.schemas import EffectivenessScore
from meta_harness.skill_adoption import _sidecar_path
from meta_harness.skill_effectiveness import compute_effectiveness_score
from meta_harness.skill_feedback import _operator_ratings_path

_CASES_DIR = Path(__file__).resolve().parent.parent / "eval" / "cases"
_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# YAML case loader
# ---------------------------------------------------------------------------


def _load_g1_cases() -> list[dict]:
    """Load the 5 G1 eval-case YAML files (cases 16-20)."""
    cases: list[dict] = []
    for case_path in sorted(_CASES_DIR.glob("1[6-9]_*.yaml")) + sorted(
        _CASES_DIR.glob("20_*.yaml")
    ):
        data = yaml.safe_load(case_path.read_text(encoding="utf-8"))
        data["_file"] = case_path.name
        cases.append(data)
    return cases


G1_CASES = _load_g1_cases()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _audit_log(tmp_path: Path, name: str = "test-run") -> AuditLog:
    return AuditLog(tmp_path / f"audit-{name}.jsonl", agent="test", run_id=name)


def _write_sidecar_events(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    events: list[dict],
) -> Path:
    path = _sidecar_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if events:
        with open(path, "w", encoding="utf-8") as f:
            for i, evt in enumerate(events):
                action = evt["action"]
                run_id = evt.get("run_id", f"run_{i:03d}")
                outcome = evt.get("outcome", "success")
                out: dict[str, object] = {
                    "action": action,
                    "agent_id": agent_id,
                    "skill_id": skill_id,
                    "tenant_id": "default",
                    "run_id": run_id,
                }
                if action == "agent.skill.loaded":
                    out["loaded_at"] = _NOW.isoformat()
                    out["contributed_at"] = None
                elif action == "agent.skill.contributed":
                    out["loaded_at"] = None
                    out["contributed_at"] = _NOW.isoformat()
                    out["outcome"] = outcome
                f.write(json.dumps(out, sort_keys=True) + "\n")
    return path


def _write_operator_ratings(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    ratings: list[dict],
) -> Path:
    path = _operator_ratings_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if ratings:
        with open(path, "w", encoding="utf-8") as f:
            for i, r in enumerate(ratings):
                payload = {
                    "action": "agent.skill.operator_rated",
                    "skill_id": skill_id,
                    "agent_id": agent_id,
                    "tenant_id": "default",
                    "rating": r["rating"],
                    "rated_by": r.get("rated_by", f"operator-{i}"),
                    "rated_at": r.get("rated_at", _NOW.isoformat()),
                }
                if r.get("note"):
                    payload["note"] = r["note"]
                f.write(json.dumps(payload, sort_keys=True) + "\n")
    return path


def _seed_from_case(
    case: dict, workspace_root: Path, agent_id_override: str | None = None
) -> tuple[str, str]:
    """Seed sidecar data from a YAML case fixture. Returns (agent_id, skill_id)."""
    fixture = case["fixture"]
    agent_id = agent_id_override or fixture["agent_id"]
    skill_id = fixture["skill_id"]
    _write_sidecar_events(workspace_root, agent_id, skill_id, fixture.get("sidecar_events", []))
    _write_operator_ratings(workspace_root, agent_id, skill_id, fixture.get("operator_ratings", []))
    return agent_id, skill_id


def _assert_op(actual: float | str | None, expected_spec: dict, context: str) -> None:
    """Assert an operator-based comparison from the YAML expected dict."""
    op = expected_spec["op"]
    expected_val = expected_spec["value"]
    if op == "eq":
        assert actual == expected_val, f"{context}: expected {expected_val!r}, got {actual!r}"
    elif op == "lt":
        assert isinstance(actual, (int, float)), (
            f"{context}: expected numeric for lt, got {type(actual)}"
        )
        assert actual < expected_val, f"{context}: expected < {expected_val}, got {actual}"
    elif op == "lte":
        assert isinstance(actual, (int, float)), (
            f"{context}: expected numeric for lte, got {type(actual)}"
        )
        assert actual <= expected_val, f"{context}: expected <= {expected_val}, got {actual}"
    elif op == "gt":
        assert isinstance(actual, (int, float)), (
            f"{context}: expected numeric for gt, got {type(actual)}"
        )
        assert actual > expected_val, f"{context}: expected > {expected_val}, got {actual}"
    elif op == "gte":
        assert isinstance(actual, (int, float)), (
            f"{context}: expected numeric for gte, got {type(actual)}"
        )
        assert actual >= expected_val, f"{context}: expected >= {expected_val}, got {actual}"
    else:
        pytest.fail(f"unknown op {op!r} in {context}")


def _count_audit_actions(audit_log: AuditLog, action: str) -> int:
    """Count how many times *action* appears in the audit log."""
    if not audit_log.path.is_file():
        return 0
    count = 0
    from charter.audit import AuditEntry

    for line in audit_log.path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entry = AuditEntry.from_json(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if entry.action == action:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Case 16 — adoption axis
# ---------------------------------------------------------------------------


def test_case_16_adoption_axis_increments_on_loaded_events(tmp_path: Path) -> None:
    case = next(c for c in G1_CASES if c["case_id"].startswith("16"))
    agent_id, skill_id = _seed_from_case(case, tmp_path)
    al = _audit_log(tmp_path, "case-16")

    score = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al,
        workspace_root=tmp_path,
    )

    exp = case["expected"]
    if exp.get("adoption_confidence"):
        _assert_op(
            score.axes_breakdown.adoption.confidence,
            exp["adoption_confidence"],
            "adoption_confidence",
        )
    assert (score.global_score is not None) == exp.get("global_score_not_null", False)
    assert (score.reason is None) == exp.get("reason_null", False)
    assert (score.axes_breakdown is not None) == exp.get("axes_breakdown_not_null", False)


# ---------------------------------------------------------------------------
# Case 17 — harmful rating drops composite
# ---------------------------------------------------------------------------


def test_case_17_harmful_rating_drops_composite(tmp_path: Path) -> None:
    case = next(c for c in G1_CASES if c["case_id"].startswith("17"))
    agent_id, skill_id = _seed_from_case(case, tmp_path)
    al = _audit_log(tmp_path, "case-17")

    score = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al,
        workspace_root=tmp_path,
    )

    exp = case["expected"]
    # Feedback axis is computed — verify it registered the harmful rating.
    fb = score.axes_breakdown.feedback
    if exp.get("feedback_score"):
        _assert_op(fb.score, exp["feedback_score"], "feedback_score")
    if exp.get("feedback_confidence"):
        _assert_op(fb.confidence, exp["feedback_confidence"], "feedback_confidence")
    if exp.get("global_score"):
        _assert_op(score.global_score, exp["global_score"], "global_score")


# ---------------------------------------------------------------------------
# Case 18 — non-emitting agent
# ---------------------------------------------------------------------------


def test_case_18_non_emitting_agent_zero_confidence(tmp_path: Path) -> None:
    case = next(c for c in G1_CASES if c["case_id"].startswith("18"))
    agent_id, skill_id = _seed_from_case(case, tmp_path)
    al = _audit_log(tmp_path, "case-18")

    score = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al,
        workspace_root=tmp_path,
    )
    # Apply the backwards-compat reason upgrade.
    score = apply_backwards_compat_reason(
        score,
        agent_id=agent_id,
        audit_log=al,
        workspace_root=tmp_path,
    )

    exp = case["expected"]
    if exp.get("confidence"):
        _assert_op(score.confidence, exp["confidence"], "confidence")
    if exp.get("reason"):
        _assert_op(score.reason.value if score.reason else None, exp["reason"], "reason")
    assert (score.global_score is None) == exp.get("global_score_null", False)
    assert (score.axes_breakdown is None) == exp.get("axes_breakdown_null", False)


# ---------------------------------------------------------------------------
# Case 19 — idempotency
# ---------------------------------------------------------------------------


def test_case_19_aggregator_idempotent(tmp_path: Path) -> None:
    case = next(c for c in G1_CASES if c["case_id"].startswith("19"))
    agent_id, skill_id = _seed_from_case(case, tmp_path)

    # First invocation.
    al1 = _audit_log(tmp_path, "case-19a")
    score1 = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al1,
        workspace_root=tmp_path,
    )
    write_effectiveness_score(score1, audit_log=al1, workspace_root=tmp_path)
    count1 = _count_audit_actions(al1, "meta_harness.skill.effectiveness_updated")

    # Second invocation — same data, no new events.
    al2 = _audit_log(tmp_path, "case-19b")
    score2 = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al2,
        workspace_root=tmp_path,
    )
    write_effectiveness_score(score2, audit_log=al2, workspace_root=tmp_path)
    count2 = _count_audit_actions(al2, "meta_harness.skill.effectiveness_updated")

    assert score1.global_score == score2.global_score, (
        f"second score {score2.global_score} != first {score1.global_score}"
    )
    assert score1.confidence == score2.confidence, (
        f"second confidence {score2.confidence} != first {score1.confidence}"
    )
    # First invocation emits 1 event (new score). Second invocation emits 0
    # (idempotent — score unchanged).
    assert count1 == 1, f"first invocation should emit 1 effectiveness_updated, got {count1}"
    assert count2 == 0, (
        f"second invocation should emit 0 effectiveness_updated (idempotent), got {count2}"
    )


# ---------------------------------------------------------------------------
# Case 20 — GEPA API shape
# ---------------------------------------------------------------------------


def test_case_20_gepa_api_returns_correct_shape(tmp_path: Path) -> None:
    case = next(c for c in G1_CASES if c["case_id"].startswith("20"))
    agent_id, skill_id = _seed_from_case(case, tmp_path)
    al = _audit_log(tmp_path, "case-20")

    score = compute_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        audit_log=al,
        workspace_root=tmp_path,
    )
    write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)

    # Read back via the GEPA-consumed API.
    cached = get_effectiveness_score(
        skill_id=skill_id,
        agent_id=agent_id,
        workspace_root=tmp_path,
    )
    assert cached is not None, "get_effectiveness_score returned None after write"

    exp = case["expected"]
    assert isinstance(cached, EffectivenessScore)

    if exp.get("has_global_score"):
        assert cached.global_score is not None
    if exp.get("has_confidence"):
        assert isinstance(cached.confidence, float)
    if exp.get("has_by_agent"):
        assert isinstance(cached.by_agent, dict)
    if exp.get("has_by_tenant"):
        assert isinstance(cached.by_tenant, dict)
    if exp.get("has_axes_breakdown"):
        assert cached.axes_breakdown is not None

    axes = cached.axes_breakdown
    if exp.get("axes_breakdown_has_adoption"):
        assert hasattr(axes, "adoption") and axes.adoption is not None
    if exp.get("axes_breakdown_has_outcome"):
        assert hasattr(axes, "outcome") and axes.outcome is not None
    if exp.get("axes_breakdown_has_feedback"):
        assert hasattr(axes, "feedback") and axes.feedback is not None

    if exp.get("global_score_type"):
        assert isinstance(cached.global_score, float)
    if exp.get("confidence_type"):
        assert isinstance(cached.confidence, float)
    if exp.get("adoption_score_type"):
        assert isinstance(axes.adoption.score, float)
    if exp.get("outcome_score_type"):
        assert isinstance(axes.outcome.score, float)
    if exp.get("feedback_score_type"):
        assert isinstance(axes.feedback.score, float)

    if exp.get("reason_null"):
        assert cached.reason is None, f"reason should be None, got {cached.reason}"


# ---------------------------------------------------------------------------
# Regression guard — existing 15 cases are 15 YAML files
# ---------------------------------------------------------------------------


def test_g1_eval_cases_count_is_5() -> None:
    """v0.2 baseline: 15 cases. G1 adds 5. G2 (Task 7) adds 5 more."""
    assert len(G1_CASES) == 5, f"expected 5 G1 eval cases, got {len(G1_CASES)}"


def test_eval_cases_total_is_25() -> None:
    """Total eval cases across v0.2 (15) + G1 (5) + G2 (5)."""
    all_cases = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(all_cases) == 25, (
        f"expected 25 total eval cases, got {len(all_cases)}: {[f.name for f in all_cases]}"
    )
