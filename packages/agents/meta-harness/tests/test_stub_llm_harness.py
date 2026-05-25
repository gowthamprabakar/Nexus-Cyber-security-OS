"""Tests — Task 14 stub-LLM eval harness + WI-3 byte-equal probe.

Validates:

1.  ``eval/stub_responses/`` directory exists.
2.  Each YAML case has a matching ``stub_responses/<case_id>/``
    directory.
3.  Each stub directory ships a ``responses.json`` file.
4.  Each ``responses.json`` parses as a JSON list of strings.
5.  ``_resolve_canned_responses`` returns the stub-file list when
    present.
6.  ``_resolve_canned_responses`` returns ``[]`` when no file
    exists.
7.  ``_resolve_canned_responses`` raises on a malformed file.
8.  v0.1: every case ships an EMPTY responses list (A.4 doesn't
    consume an LLM directly in v0.1; the hook is here for the
    v0.2 expansion).

**WI-3 acceptance — byte-equal across reruns.** Running each of
the 10 bundled cases twice through ``MetaHarnessEvalRunner.run``
MUST produce byte-equal serialized ``RunOutcome`` payloads
(``actuals`` dict + ``failure_reason``). Any drift signals a
hidden non-determinism source and is treated as a v0.1 bug.

Plus 10 sanity tests asserting each bundled case continues to
pass under the stub-harness layout (one parameterized test per
case).

Total: 28 tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from eval_framework.cases import load_case_file
from meta_harness.eval_runner import MetaHarnessEvalRunner, _resolve_canned_responses

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"
_STUB_DIR = Path(__file__).parent.parent / "eval" / "stub_responses"

_CASE_FILES = sorted(_CASES_DIR.glob("*.yaml"))
_CASE_IDS = [load_case_file(p).case_id for p in _CASE_FILES]

# G1 effectiveness-scoring cases (16-20) are validated by
# ``test_g1_eval_cases.py`` — they do not use MetaHarnessEvalRunner.
_RUNNER_CASE_FILES = [
    p
    for p in _CASE_FILES
    if not any(p.stem.startswith(prefix) for prefix in ("16_", "17_", "18_", "19_", "20_"))
]


def _all_stub_dirs() -> list[Path]:
    return sorted([p for p in _STUB_DIR.glob("*") if p.is_dir()])


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


def test_stub_responses_dir_exists() -> None:
    assert _STUB_DIR.is_dir(), f"stub_responses dir missing: {_STUB_DIR}"


def test_every_case_has_a_stub_responses_directory() -> None:
    case_ids = set(_CASE_IDS)
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
        assert all(isinstance(r, str) for r in raw), f"{case_dir} has non-string entries"


def test_v01_every_case_ships_empty_responses_list() -> None:
    """A.4 v0.1 doesn't consume an LLM directly; every case's stub
    responses list is empty. v0.2 may populate them when meta-eval
    cases need LLM-driven assertions."""
    for case_dir in _all_stub_dirs():
        raw = json.loads((case_dir / "responses.json").read_text(encoding="utf-8"))
        assert raw == [], f"{case_dir.name}/responses.json should be [] in v0.1; got {raw!r}"


# ---------------------------------------------------------------------------
# _resolve_canned_responses precedence
# ---------------------------------------------------------------------------


def test_resolver_returns_stub_file_when_present() -> None:
    """Build a fake case_id whose stub_responses file exists; resolver
    must return the file contents."""
    # The first bundled case is `01_clean_batch`; its responses.json
    # ships an empty list. The resolver must return that list.
    case = load_case_file(_CASE_FILES[0])
    assert _resolve_canned_responses(case) == []


def test_resolver_returns_empty_list_when_no_stub_file(tmp_path: Path) -> None:
    """A case whose case_id doesn't correspond to any shipped
    stub_responses dir resolves to []."""
    from eval_framework.cases import EvalCase

    fake = EvalCase(case_id="non_existent_case_id_xyz", description="t")
    assert _resolve_canned_responses(fake) == []


def test_resolver_raises_on_malformed_responses_json(tmp_path: Path) -> None:
    """Synthetic case_id pointing at a malformed responses.json."""
    from eval_framework.cases import EvalCase

    # Create a temporary case_id that lands inside the real stub dir.
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
        # Clean up so subsequent test runs don't see the synthetic dir.
        bad_path.unlink(missing_ok=True)
        target.rmdir()


# ---------------------------------------------------------------------------
# WI-3 byte-equal across reruns (one parameterized test per case)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_filename", [p.name for p in _RUNNER_CASE_FILES])
@pytest.mark.asyncio
async def test_wi3_byte_equal_across_reruns(case_filename: str, tmp_path: Path) -> None:
    """Run the case twice; assert the serialized RunOutcome payloads
    are byte-equal across reruns. Strips legitimately-variable fields
    (durations) before comparison; actuals + failure_reason must
    match exactly."""
    case = load_case_file(_CASES_DIR / case_filename)
    runner = MetaHarnessEvalRunner()

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

    Strips fields that legitimately vary across runs even under
    identical inputs (paths inside ``actuals`` would be one
    example, but v0.1's meta-harness actuals are pure counts).
    """
    passed, failure_reason, actuals, _audit_log = outcome
    payload = {
        "passed": passed,
        "failure_reason": failure_reason,
        "actuals": actuals,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Each bundled case still passes (sanity — guard against the
# stub-harness layout breaking the previously-passing 10/10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_filename", [p.name for p in _RUNNER_CASE_FILES])
@pytest.mark.asyncio
async def test_each_bundled_case_still_passes(case_filename: str, tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / case_filename)
    runner = MetaHarnessEvalRunner()
    workspace = tmp_path / case.case_id
    passed, failure_reason, _actuals, _log = await runner.run(case, workspace=workspace)
    assert passed, f"case {case.case_id} failed under stub harness: {failure_reason}"
