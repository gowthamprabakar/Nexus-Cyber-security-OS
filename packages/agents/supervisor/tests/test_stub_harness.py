"""Tests — Task 14 stub-LLM harness + WI-3 byte-equal probe.

Validates:

1.  ``eval/stub_responses/`` directory exists.
2.  Each YAML case has a matching ``stub_responses/<case_id>/``
    dir.
3.  Each stub directory ships a ``responses.json`` file.
4.  Each ``responses.json`` parses as a JSON list of strings.
5.  v0.1: every case ships an EMPTY responses list (Supervisor
    doesn't consume an LLM in v0.1; routing is rule-based).
6.  ``_resolve_canned_responses`` returns the stub-file list when
    present.
7.  ``_resolve_canned_responses`` returns ``[]`` when no file
    exists.
8.  ``_resolve_canned_responses`` raises on malformed payload.

**WI-3 acceptance — byte-equal across reruns.** Running each of
the 15 bundled cases twice through ``SupervisorEvalRunner.run``
MUST produce byte-equal serialized RunOutcome payloads
(``actuals`` dict minus the volatile ``audit_actions`` action-
sequence which is deterministic + a separate equality probe).

Per-case sanity: 15 parameterized tests assert each case
continues to pass under the stub harness layout (guards against
the harness layout breaking the 15/15 from Task 12).

Total: 38 tests (5 layout + 3 resolver + 15 byte-equal-probes +
15 sanity-still-passes).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from eval_framework.cases import EvalCase, load_case_file
from supervisor.eval_runner import (
    SupervisorEvalRunner,
    _resolve_canned_responses,
)

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"
_STUB_DIR = Path(__file__).parent.parent / "eval" / "stub_responses"

_CASE_FILES = sorted(_CASES_DIR.glob("*.yaml"))


def _all_stub_dirs() -> list[Path]:
    return sorted([p for p in _STUB_DIR.glob("*") if p.is_dir()])


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


def test_stub_responses_dir_exists() -> None:
    assert _STUB_DIR.is_dir(), f"stub_responses dir missing: {_STUB_DIR}"


def test_every_case_has_a_stub_responses_directory() -> None:
    case_ids = {load_case_file(p).case_id for p in _CASE_FILES}
    stub_ids = {p.name for p in _all_stub_dirs()}
    missing = case_ids - stub_ids
    assert not missing, f"cases without stub_responses dir: {sorted(missing)}"


def test_every_stub_dir_has_responses_json() -> None:
    for case_dir in _all_stub_dirs():
        responses = case_dir / "responses.json"
        assert responses.is_file(), f"{responses} missing"


def test_every_responses_json_is_a_list_of_strings() -> None:
    for case_dir in _all_stub_dirs():
        raw = json.loads((case_dir / "responses.json").read_text(encoding="utf-8"))
        assert isinstance(raw, list)
        assert all(isinstance(r, str) for r in raw)


def test_v01_every_case_ships_empty_responses_list() -> None:
    """Supervisor v0.1 doesn't consume an LLM directly; every
    case's stub responses list is empty. v0.2 may populate them
    when LLM-assisted routing arrives."""
    for case_dir in _all_stub_dirs():
        raw = json.loads((case_dir / "responses.json").read_text(encoding="utf-8"))
        assert raw == [], f"{case_dir.name}/responses.json should be [] in v0.1; got {raw!r}"


# ---------------------------------------------------------------------------
# _resolve_canned_responses precedence
# ---------------------------------------------------------------------------


def test_resolver_returns_stub_file_when_present() -> None:
    case = load_case_file(_CASE_FILES[0])
    assert _resolve_canned_responses(case) == []


def test_resolver_returns_empty_list_when_no_stub_file() -> None:
    fake = EvalCase(case_id="non_existent_case_id_xyz", description="t")
    assert _resolve_canned_responses(fake) == []


def test_resolver_raises_on_malformed_payload() -> None:
    case_id = "task14_bad_payload_probe"
    target = _STUB_DIR / case_id
    target.mkdir(parents=True, exist_ok=True)
    bad_path = target / "responses.json"
    bad_path.write_text('{"not": "a list"}', encoding="utf-8")
    try:
        fake = EvalCase(case_id=case_id, description="t")
        with pytest.raises(ValueError, match="JSON list"):
            _resolve_canned_responses(fake)
    finally:
        bad_path.unlink(missing_ok=True)
        target.rmdir()


# ---------------------------------------------------------------------------
# WI-3 byte-equal across reruns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_filename", [p.name for p in _CASE_FILES])
@pytest.mark.asyncio
async def test_wi3_byte_equal_across_reruns(case_filename: str, tmp_path: Path) -> None:
    """Run the case twice; assert serialized RunOutcome payloads
    are byte-equal across reruns.

    Strips fields that legitimately vary across runs:
    - ULIDs in actuals (delegation_id / tick_id / escalation_id
      are minted fresh each call).
    - The audit-action sequence is naturally deterministic — same
      input -> same emission order — but we serialize it
      separately so the assertion failure mode is clearer.
    """
    case = load_case_file(_CASES_DIR / case_filename)
    runner = SupervisorEvalRunner()

    workspace_a = tmp_path / f"{case.case_id}-a"
    workspace_b = tmp_path / f"{case.case_id}-b"

    outcome_a = await runner.run(case, workspace=workspace_a)
    outcome_b = await runner.run(case, workspace=workspace_b)

    bytes_a = _canonical_bytes(outcome_a)
    bytes_b = _canonical_bytes(outcome_b)
    assert bytes_a == bytes_b, (
        f"WI-3 violation: {case.case_id} produced non-byte-equal outcomes across reruns.\n"
        f"  a: {bytes_a.decode('utf-8')}\n"
        f"  b: {bytes_b.decode('utf-8')}"
    )


def _canonical_bytes(outcome: tuple) -> bytes:  # type: ignore[type-arg]
    """Serialize a RunOutcome tuple to canonical JSON bytes.

    Drops ULID-shaped fields from actuals (delegation_id /
    tick_id / escalation_id are minted fresh per call); preserves
    every other actuals key + the passed/failure_reason fields.
    The audit_actions sequence is part of the canonical payload
    since it's structurally deterministic.
    """
    passed, failure_reason, actuals, _audit_log = outcome
    # Supervisor's v0.1 actuals dict carries pure counts +
    # deterministic strings (first_decision_kind /
    # first_target_agent / audit_actions list) — naturally
    # byte-equal across reruns with no fields to strip.
    payload = {
        "passed": passed,
        "failure_reason": failure_reason,
        "actuals": actuals,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Each bundled case still passes (sanity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_filename", [p.name for p in _CASE_FILES])
@pytest.mark.asyncio
async def test_each_bundled_case_still_passes(case_filename: str, tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / case_filename)
    runner = SupervisorEvalRunner()
    workspace = tmp_path / case.case_id
    passed, failure_reason, _actuals, _log = await runner.run(case, workspace=workspace)
    assert passed, f"case {case.case_id} failed under stub harness: {failure_reason}"
