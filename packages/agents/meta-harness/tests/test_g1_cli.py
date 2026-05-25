"""G1 CLI tests — Task 11 (score-effectiveness + rate-skill commands).

12 tests covering Click command behavior via CliRunner.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from click.testing import CliRunner
from meta_harness.cli import main

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


def _runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Sidecar helpers
# ---------------------------------------------------------------------------


def _write_run_events(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
    path = workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "run-events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, sort_keys=True) + "\n")
    return path


def _loaded_event(
    skill_id: str,
    agent_id: str,
    run_id: str,
    tenant_id: str = "default",
) -> dict[str, object]:
    return {
        "action": "agent.skill.loaded",
        "agent_id": agent_id,
        "contributed_at": None,
        "loaded_at": _NOW.isoformat(),
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


def _contributed_event(
    skill_id: str,
    agent_id: str,
    run_id: str,
    outcome: str = "success",
    tenant_id: str = "default",
) -> dict[str, object]:
    return {
        "action": "agent.skill.contributed",
        "agent_id": agent_id,
        "contributed_at": _NOW.isoformat(),
        "loaded_at": None,
        "outcome": outcome,
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


def _seed_agent_skill(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    load_count: int = 10,
    success_count: int = 10,
    tenant_id: str = "default",
) -> None:
    """Seed a skill with enough events for full confidence on adoption and outcome."""
    lines: list[dict[str, object]] = []
    for i in range(load_count):
        lines.append(_loaded_event(skill_id, agent_id, f"r{i}", tenant_id=tenant_id))
    for i in range(success_count):
        lines.append(
            _contributed_event(skill_id, agent_id, f"s{i}", "success", tenant_id=tenant_id)
        )
    _write_run_events(workspace_root, agent_id, skill_id, lines)


# ---------------------------------------------------------------------------
# score-effectiveness tests
# ---------------------------------------------------------------------------


def test_g1_score_effectiveness_no_flags_aggregates_all(tmp_path: Path) -> None:
    """Without flags, aggregates all deployed skills across all agents."""
    _seed_agent_skill(tmp_path, "agent-a", "sk_a")
    _seed_agent_skill(tmp_path, "agent-b", "sk_b")

    runner = _runner()
    result = runner.invoke(main, ["score-effectiveness", "--workspace-root", str(tmp_path)])
    assert result.exit_code == 0
    assert "agent-a" in result.output
    assert "agent-b" in result.output
    assert "sk_a" in result.output
    assert "sk_b" in result.output


def test_g1_score_effectiveness_agent_filter(tmp_path: Path) -> None:
    """--agent scopes aggregation to a single agent."""
    _seed_agent_skill(tmp_path, "agent-a", "sk_a")
    _seed_agent_skill(tmp_path, "agent-b", "sk_b")

    runner = _runner()
    result = runner.invoke(
        main, ["score-effectiveness", "--agent", "agent-a", "--workspace-root", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "agent-a" in result.output
    assert "sk_a" in result.output
    assert "agent-b" not in result.output
    assert "sk_b" not in result.output


def test_g1_score_effectiveness_skill_and_agent(tmp_path: Path) -> None:
    """--skill + --agent computes score for a single skill."""
    _seed_agent_skill(tmp_path, "agent-x", "sk_target")

    runner = _runner()
    result = runner.invoke(
        main,
        [
            "score-effectiveness",
            "--agent",
            "agent-x",
            "--skill",
            "sk_target",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "sk_target" in result.output


def test_g1_score_effectiveness_skill_without_agent_errors(tmp_path: Path) -> None:
    """--skill without --agent produces a user-friendly error."""
    runner = _runner()
    result = runner.invoke(
        main, ["score-effectiveness", "--skill", "sk_x", "--workspace-root", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "ERROR" in result.stderr


def test_g1_score_effectiveness_writes_sidecar(tmp_path: Path) -> None:
    """score-effectiveness writes effectiveness.json to the sidecar."""
    _seed_agent_skill(tmp_path, "agent-w", "sk_w")

    runner = _runner()
    result = runner.invoke(main, ["score-effectiveness", "--workspace-root", str(tmp_path)])
    assert result.exit_code == 0
    sidecar = tmp_path / ".nexus" / "deployed-skills" / "agent-w" / "sk_w" / "effectiveness.json"
    assert sidecar.is_file()
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["skill_id"] == "sk_w"
    assert data["global_score"] is not None


def test_g1_score_effectiveness_empty_workspace(tmp_path: Path) -> None:
    """Empty workspace (no deployed skills) produces a graceful message."""
    runner = _runner()
    result = runner.invoke(main, ["score-effectiveness", "--workspace-root", str(tmp_path)])
    assert result.exit_code == 0
    assert "no deployed skills" in result.output


def test_g1_score_effectiveness_tenant_scoping(tmp_path: Path) -> None:
    """--tenant scopes aggregation to a specific tenant."""
    _seed_agent_skill(tmp_path, "agent-t", "sk_t1", tenant_id="acme")
    _seed_agent_skill(tmp_path, "agent-t", "sk_t2", tenant_id="default")

    runner = _runner()
    result = runner.invoke(
        main, ["score-effectiveness", "--tenant", "acme", "--workspace-root", str(tmp_path)]
    )
    assert result.exit_code == 0
    # sk_t1 is "acme", sk_t2 is "default" — only sk_t1 appears for acme tenant.
    # Both will be in the output table but only sk_t1 gets a score (sk_t2 confidence=0).
    assert "sk_t1" in result.output


# ---------------------------------------------------------------------------
# rate-skill tests
# ---------------------------------------------------------------------------


def test_g1_rate_skill_useful_writes_audit_and_sidecar(tmp_path: Path) -> None:
    """Rating a skill as useful writes to audit chain and sidecar projection."""
    runner = _runner()
    result = runner.invoke(
        main,
        [
            "rate-skill",
            "sk_r1",
            "--rating",
            "useful",
            "--agent",
            "ag-r1",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "rated sk_r1 as useful" in result.output

    # Sidecar projection exists.
    sidecar = tmp_path / ".nexus" / "deployed-skills" / "ag-r1" / "sk_r1" / "operator-ratings.jsonl"
    assert sidecar.is_file()
    records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 1
    assert records[0]["rating"] == "useful"
    assert records[0]["skill_id"] == "sk_r1"


def test_g1_rate_skill_harmful_with_note(tmp_path: Path) -> None:
    """--note is captured in the operator rating payload."""
    runner = _runner()
    result = runner.invoke(
        main,
        [
            "rate-skill",
            "sk_note",
            "--rating",
            "harmful",
            "--note",
            "caused incorrect output",
            "--agent",
            "ag-note",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "rated sk_note as harmful" in result.output
    assert "note: caused incorrect output" in result.output

    sidecar = (
        tmp_path / ".nexus" / "deployed-skills" / "ag-note" / "sk_note" / "operator-ratings.jsonl"
    )
    records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records[0]["note"] == "caused incorrect output"


def test_g1_rate_skill_neutral_with_note_file(tmp_path: Path) -> None:
    """--note-file reads a multi-line note from a file."""
    note_path = tmp_path / "note.txt"
    note_path.write_text("multi\nline\nnote", encoding="utf-8")

    runner = _runner()
    result = runner.invoke(
        main,
        [
            "rate-skill",
            "sk_nf",
            "--rating",
            "neutral",
            "--note-file",
            str(note_path),
            "--agent",
            "ag-nf",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    sidecar = tmp_path / ".nexus" / "deployed-skills" / "ag-nf" / "sk_nf" / "operator-ratings.jsonl"
    records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records[0]["note"] == "multi\nline\nnote"


def test_g1_rate_skill_no_rating_flag_errors(tmp_path: Path) -> None:
    """Missing --rating produces a Click error (required)."""
    runner = _runner()
    result = runner.invoke(main, ["rate-skill", "sk_nr", "--workspace-root", str(tmp_path)])
    assert result.exit_code != 0


def test_g1_rate_skill_appends_to_existing_sidecar(tmp_path: Path) -> None:
    """Multiple ratings for the same skill append to the same sidecar file."""
    runner = _runner()
    args = ["--agent", "ag-multi", "--workspace-root", str(tmp_path)]
    r1 = runner.invoke(main, ["rate-skill", "sk_multi", "--rating", "useful", *args])
    assert r1.exit_code == 0
    r2 = runner.invoke(main, ["rate-skill", "sk_multi", "--rating", "harmful", *args])
    assert r2.exit_code == 0

    sidecar = (
        tmp_path / ".nexus" / "deployed-skills" / "ag-multi" / "sk_multi" / "operator-ratings.jsonl"
    )
    records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 2
    assert {r["rating"] for r in records} == {"useful", "harmful"}


# ---------------------------------------------------------------------------
# CF #2 — score-effectiveness write failure
# ---------------------------------------------------------------------------


def test_g1_score_effectiveness_cf2_storage_failure(tmp_path: Path, mocker) -> None:
    """Forced write failure → non-zero exit code."""
    _seed_agent_skill(tmp_path, "agent-cf2", "sk_cf2")

    mocker.patch(
        "meta_harness.cli.write_effectiveness_score",
        side_effect=OSError("disk full"),
    )

    runner = _runner()
    result = runner.invoke(main, ["score-effectiveness", "--workspace-root", str(tmp_path)])
    assert result.exit_code != 0
    assert "FAIL" in result.stderr
