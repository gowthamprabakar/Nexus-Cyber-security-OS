"""G2 skill-selection eval cases — Task 7.

Reads the 5 YAML case files (21-25) from ``eval/cases/`` and executes
them against the real G2 deliverables (Tasks 2-6).

G2-Q2 makes the LLM the skill-selection layer — there is no ranking
algorithm and no LLM in the eval harness. So these cases verify the
**inputs and rules** the LLM acts on, deterministically:

* Cases 21-23 — seed bundled skills + G1 effectiveness sidecars, run them
  through Task 5's ``discover_agent_skills`` (real Level 0 enrichment),
  then apply the NLAH persona's documented composite rule
  (effectiveness * confidence; None = neutral; 0.0 at high confidence =
  avoid as proven-harmful — Task 6) and assert the selected skill_id.
  This is a deterministic proxy for an LLM that follows its persona.

* Cases 24-25 — assert the ``trigger_source`` → dispatch-mode
  classification a dual-mode dispatcher keys on (G2-Q1 Option E):
  EVENTS_BUS / SCHEDULED_QUEUE → autonomous (select once per run);
  OPERATOR_CLI → interactive (select once per turn). ``trigger_source``
  is validated against the real supervisor ``TriggerSource`` enum
  (Task 3). No ``skill.selected`` audit event or dispatcher exists yet
  (G2 v0.2 / agent-runtime); these cases pin the contract a future
  dispatcher must honor without adding audit constants or src changes.

No new audit-action constants, no charter/G1/G2 module changes — eval
cases + test code only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from charter.audit import AuditLog
from meta_harness.skill_discovery import discover_agent_skills
from supervisor.schemas import TriggerSource

_CASES_DIR = Path(__file__).resolve().parent.parent / "eval" / "cases"

# Persona decision-rule constants (mirror nlah/README.md "Skill selection
# guidance" — Task 6). Kept in the test, not src: the rule lives in the
# persona prose for the LLM; this is its deterministic encoding for eval.
_HIGH_CONFIDENCE = 0.8
_NEUTRAL_EFFECTIVENESS = 0.5

_MINIMAL_SKILL_MD = """---
name: {name}
description: Eval-case skill for G2 Task 7 selection signal.
version: 0.1.0
platforms:
  - nexus
target_agent: {agent_id}
category: {category}
created_by: meta_harness@g2-task-7
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
eval_gate_status: not_run
deployment_status: candidate
---

Eval-case skill body for {name}.
"""


# ---------------------------------------------------------------------------
# YAML case loader
# ---------------------------------------------------------------------------


def _load_g2_cases() -> list[dict[str, Any]]:
    """Load the 5 G2 eval-case YAML files (cases 21-25)."""
    cases: list[dict[str, Any]] = []
    for case_path in sorted(_CASES_DIR.glob("2[1-5]_*.yaml")):
        data = yaml.safe_load(case_path.read_text(encoding="utf-8"))
        data["_file"] = case_path.name
        cases.append(data)
    return cases


G2_CASES = _load_g2_cases()


def _case(prefix: str) -> dict[str, Any]:
    return next(c for c in G2_CASES if c["case_id"].startswith(prefix))


# ---------------------------------------------------------------------------
# Fixture seeding — bundled skills + G1 effectiveness sidecars
# ---------------------------------------------------------------------------


def _bundled_nlah_dir(workspace_root: Path, agent_id: str) -> Path:
    dirname = agent_id.replace("_", "-")
    return workspace_root / "packages" / "agents" / dirname / "src" / agent_id / "nlah"


def _write_bundled_skill(workspace_root: Path, agent_id: str, skill_id: str) -> None:
    skill_dir = _bundled_nlah_dir(workspace_root, agent_id) / "skills" / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    category = skill_id.split("/", 1)[0]
    name = skill_id.replace("/", "_").replace("-", "_")
    (skill_dir / "SKILL.md").write_text(
        _MINIMAL_SKILL_MD.format(name=name, agent_id=agent_id, category=category),
        encoding="utf-8",
    )


def _write_effectiveness_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float,
    confidence: float,
    tenant_id: str = "default",
) -> None:
    """Write a valid EffectivenessScore sidecar (Task 4/G1 shape).

    Only called for measured skills (score is not None). confidence here is
    always > 0, so axes_breakdown must be present per the EffectivenessScore
    validator.
    """
    path = (
        workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "global_score": global_score,
        "confidence": confidence,
        "by_agent": {},
        "by_tenant": {},
        "axes_breakdown": {
            "adoption": {"score": global_score, "confidence": confidence},
            "outcome": {"score": global_score, "confidence": confidence},
            "feedback": {"score": global_score, "confidence": confidence},
        },
        "reason": None,
        "computed_at": "2026-05-27T12:00:00+00:00",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _seed_selection_case(
    case: dict[str, Any], workspace_root: Path
) -> tuple[str, dict[str, float]]:
    """Seed bundled skills + sidecars from a 21-23 fixture.

    Returns (agent_id, topical_fit_by_skill_id).
    """
    fixture = case["fixture"]
    agent_id = fixture["agent_id"]
    tenant_id = fixture.get("tenant_id", "default")
    topical_fit: dict[str, float] = {}
    for skill in fixture["skills"]:
        skill_id = skill["skill_id"]
        _write_bundled_skill(workspace_root, agent_id, skill_id)
        topical_fit[skill_id] = float(skill["topical_fit"])
        score = skill["effectiveness_score"]
        if score is not None:
            _write_effectiveness_sidecar(
                workspace_root,
                agent_id,
                skill_id,
                global_score=float(score),
                confidence=float(skill["effectiveness_confidence"]),
                tenant_id=tenant_id,
            )
    return agent_id, topical_fit


# ---------------------------------------------------------------------------
# Persona selection rule (deterministic encoding of Task 6 guidance)
# ---------------------------------------------------------------------------


def _composite(entry: object) -> float:
    """effectiveness_score * effectiveness_confidence, with None = neutral."""
    score = entry.effectiveness_score  # type: ignore[attr-defined]
    if score is None:
        return _NEUTRAL_EFFECTIVENESS
    conf = entry.effectiveness_confidence or 0.0  # type: ignore[attr-defined]
    return float(score) * float(conf)


def _is_proven_harmful(entry: object) -> bool:
    """0.0 effectiveness at high confidence → persona says avoid."""
    score = entry.effectiveness_score  # type: ignore[attr-defined]
    conf = entry.effectiveness_confidence or 0.0  # type: ignore[attr-defined]
    return score == 0.0 and float(conf) >= _HIGH_CONFIDENCE


def _persona_select(entries: object, topical_fit: dict[str, float]) -> str | None:
    """Pick the skill a persona-following agent would select.

    relevance = topical_fit * (1 + composite); proven-harmful skills are
    excluded. Mirrors the NLAH "Skill selection guidance" rules.
    """
    best_id: str | None = None
    best_score: float | None = None
    for entry in entries:  # type: ignore[attr-defined]
        if _is_proven_harmful(entry):
            continue
        relevance = topical_fit[entry.skill_id] * (1.0 + _composite(entry))
        if best_score is None or relevance > best_score:
            best_id, best_score = entry.skill_id, relevance
    return best_id


# ---------------------------------------------------------------------------
# Dual-mode dispatch classifier (G2-Q1 Option E)
# ---------------------------------------------------------------------------

_AUTONOMOUS_TRIGGERS = {TriggerSource.EVENTS_BUS.value, TriggerSource.SCHEDULED_QUEUE.value}
_INTERACTIVE_TRIGGERS = {TriggerSource.OPERATOR_CLI.value}


def _classify_dispatch_mode(trigger_source: str) -> tuple[str, str]:
    """Map trigger_source → (dispatch_mode, selection_cardinality)."""
    if trigger_source in _AUTONOMOUS_TRIGGERS:
        return "autonomous", "per_run"
    if trigger_source in _INTERACTIVE_TRIGGERS:
        return "interactive", "per_turn"
    raise ValueError(f"unknown trigger_source: {trigger_source!r}")


def _expected_selection_count(trigger_source: str, turns: int) -> int:
    _, cardinality = _classify_dispatch_mode(trigger_source)
    return 1 if cardinality == "per_run" else turns


# ---------------------------------------------------------------------------
# Loader / count guards
# ---------------------------------------------------------------------------


def test_g2_eval_cases_count_is_5() -> None:
    assert len(G2_CASES) == 5, f"expected 5 G2 eval cases, got {len(G2_CASES)}"


def test_all_g2_cases_parse_with_required_keys() -> None:
    for case in G2_CASES:
        assert set(case).issuperset({"case_id", "description", "fixture", "expected"}), (
            f"{case['_file']}: missing required top-level keys"
        )


def test_eval_cases_total_is_25() -> None:
    """v0.2 baseline 15 + G1 5 + G2 5 = 25."""
    all_cases = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(all_cases) == 25, (
        f"expected 25 total eval cases, got {len(all_cases)}: {[f.name for f in all_cases]}"
    )


# ---------------------------------------------------------------------------
# Cases 21-23 — selection-signal (end-to-end through Task 5 enrichment)
# ---------------------------------------------------------------------------


def _run_selection_case(prefix: str, tmp_path: Path) -> tuple[str | None, dict[str, Any]]:
    case = _case(prefix)
    agent_id, topical_fit = _seed_selection_case(case, tmp_path)
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id=prefix)
    registry = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=audit_log)
    selected = _persona_select(registry.entries, topical_fit)
    return selected, case["expected"]


def test_case_21_prefers_high_effectiveness_skill(tmp_path: Path) -> None:
    selected, expected = _run_selection_case("21", tmp_path)
    assert selected == expected["selected_skill_id"]


def test_case_22_treats_none_score_as_neutral(tmp_path: Path) -> None:
    selected, expected = _run_selection_case("22", tmp_path)
    assert selected == expected["selected_skill_id"]


def test_case_23_avoids_proven_harmful_skill(tmp_path: Path) -> None:
    selected, expected = _run_selection_case("23", tmp_path)
    assert selected == expected["selected_skill_id"]


def test_case_21_23_enrichment_populates_signals_end_to_end(tmp_path: Path) -> None:
    """Task 5 wiring probe: measured skills surface populated effectiveness
    fields on the Level 0 entries; unmeasured skills stay None."""
    case = _case("21")
    agent_id, _ = _seed_selection_case(case, tmp_path)
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id="21-probe")
    registry = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=audit_log)
    by_id = {e.skill_id: e for e in registry.entries}
    assert by_id["iam-privesc/skill-a"].effectiveness_score == 0.9
    assert by_id["iam-privesc/skill-a"].effectiveness_confidence == 0.8
    assert by_id["iam-privesc/skill-b"].effectiveness_score == 0.3


def test_case_22_unmeasured_skill_has_none_fields(tmp_path: Path) -> None:
    case = _case("22")
    agent_id, _ = _seed_selection_case(case, tmp_path)
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="meta_harness", run_id="22-probe")
    registry = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=audit_log)
    by_id = {e.skill_id: e for e in registry.entries}
    assert by_id["iam-privesc/skill-a"].effectiveness_score is None
    assert by_id["iam-privesc/skill-a"].effectiveness_confidence is None


# ---------------------------------------------------------------------------
# Cases 24-25 — dual-mode dispatch classification
# ---------------------------------------------------------------------------


def test_case_24_autonomous_selects_per_run(tmp_path: Path) -> None:
    case = _case("24")
    fixture, expected = case["fixture"], case["expected"]
    trigger_source = fixture["trigger_source"]
    # Tie to Task 3: the value must be a real TriggerSource enum member.
    assert trigger_source in {t.value for t in TriggerSource}
    mode, cardinality = _classify_dispatch_mode(trigger_source)
    count = _expected_selection_count(trigger_source, fixture["turns"])
    assert mode == expected["dispatch_mode"]
    assert cardinality == expected["selection_cardinality"]
    assert count == expected["expected_selection_count"] == 1


def test_case_25_interactive_selects_per_turn(tmp_path: Path) -> None:
    case = _case("25")
    fixture, expected = case["fixture"], case["expected"]
    trigger_source = fixture["trigger_source"]
    assert trigger_source in {t.value for t in TriggerSource}
    mode, cardinality = _classify_dispatch_mode(trigger_source)
    count = _expected_selection_count(trigger_source, fixture["turns"])
    assert mode == expected["dispatch_mode"]
    assert cardinality == expected["selection_cardinality"]
    assert count == expected["expected_selection_count"] == fixture["turns"]


def test_dual_mode_classifier_rejects_unknown_trigger_source() -> None:
    with pytest.raises(ValueError, match="unknown trigger_source"):
        _classify_dispatch_mode("carrier_pigeon")
