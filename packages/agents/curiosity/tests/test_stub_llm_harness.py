"""Tests — Task 14 stub-LLM eval harness.

Validates:

1. Canned LLM responses live in
   ``eval/stub_responses/<case_id>/responses.json`` per case.
2. Each case directory ships a valid JSON list of strings.
3. ``_resolve_canned_responses`` precedence is
   stub-file > inline ``llm_responses`` > empty list.
4. WI-3 acceptance gate: eval-case output is **byte-equal across
   reruns** for hypotheses.md + probe_directives.json (timestamps
   stripped — datetime.now drifts between calls; the prose body
   must be identical).
5. All 10 shipped cases still pass after the refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from curiosity.eval_runner import (
    CuriosityEvalRunner,
    _resolve_canned_responses,
)
from eval_framework.cases import EvalCase, load_case_file

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"
_STUB_DIR = Path(__file__).parent.parent / "eval" / "stub_responses"


def _all_case_files() -> list[Path]:
    return sorted(_CASES_DIR.glob("*.yaml"))


def _all_stub_dirs() -> list[Path]:
    return sorted([p for p in _STUB_DIR.glob("*") if p.is_dir()])


# ---------------------------------------------------------------------------
# stub_responses/ layout
# ---------------------------------------------------------------------------


def test_stub_responses_dir_exists() -> None:
    assert _STUB_DIR.is_dir(), f"stub_responses dir missing: {_STUB_DIR}"


def test_every_case_has_a_stub_responses_directory() -> None:
    """Each YAML case must have a matching stub_responses/<case_id>/ dir."""
    case_ids = {load_case_file(p).case_id for p in _all_case_files()}
    stub_ids = {p.name for p in _all_stub_dirs()}
    missing = case_ids - stub_ids
    assert not missing, f"cases without stub_responses dir: {sorted(missing)}"


def test_every_stub_dir_has_responses_json() -> None:
    for case_dir in _all_stub_dirs():
        responses = case_dir / "responses.json"
        assert responses.is_file(), f"{responses} missing"


def test_every_responses_json_is_a_list_of_strings() -> None:
    """Some D.12 cases (clean-runs / threshold-edge / Q5-default) ship
    EMPTY responses lists — they short-circuit the LLM call. The
    contract is just 'list of strings', not 'non-empty list of strings'."""
    for case_dir in _all_stub_dirs():
        raw = json.loads((case_dir / "responses.json").read_text(encoding="utf-8"))
        assert isinstance(raw, list)
        assert all(isinstance(r, str) for r in raw), f"{case_dir} has non-string entries"


# ---------------------------------------------------------------------------
# _resolve_canned_responses precedence
# ---------------------------------------------------------------------------


def test_resolver_prefers_stub_file_over_inline_fixture() -> None:
    """Stub file present + inline llm_responses present -> stub wins.
    Pick a case that ships a non-empty stub responses list so the test
    distinguishes."""
    # 02-single-region-gap has 1 response in its stub file
    case_file = _CASES_DIR / "02-single-region-gap.yaml"
    a_case = load_case_file(case_file)
    case = a_case.model_copy(
        update={"fixture": {**a_case.fixture, "llm_responses": ["INLINE_ONLY"]}}
    )
    resolved = _resolve_canned_responses(case)
    assert "INLINE_ONLY" not in resolved
    assert len(resolved) == 1


def test_resolver_falls_back_to_inline_when_no_stub_file() -> None:
    """Case_id with no stub dir -> inline llm_responses used."""
    inline = ["a", "b", "c"]
    case = EvalCase(
        case_id="no_such_stub_dir_anywhere",
        description="x",
        fixture={"llm_responses": inline},
    )
    assert _resolve_canned_responses(case) == inline


def test_resolver_returns_empty_when_no_stub_and_no_inline() -> None:
    case = EvalCase(case_id="completely_empty", description="x", fixture={})
    assert _resolve_canned_responses(case) == []


def test_resolver_rejects_malformed_stub_json(tmp_path: Path) -> None:
    """responses.json that isn't a JSON list -> ValueError."""
    from curiosity import eval_runner as runner_mod

    bad_dir = tmp_path / "stub_responses" / "bad_case"
    bad_dir.mkdir(parents=True)
    (bad_dir / "responses.json").write_text('{"not": "a list"}', encoding="utf-8")

    case = EvalCase(case_id="bad_case", description="x")
    original_root = runner_mod._STUB_RESPONSES_ROOT
    runner_mod._STUB_RESPONSES_ROOT = tmp_path / "stub_responses"
    try:
        with pytest.raises(ValueError, match="must be a JSON list"):
            _resolve_canned_responses(case)
    finally:
        runner_mod._STUB_RESPONSES_ROOT = original_root


# ---------------------------------------------------------------------------
# WI-3 — byte-equal across reruns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_file",
    _all_case_files(),
    ids=lambda p: p.stem,
)
async def test_eval_output_byte_equal_across_two_runs(case_file: Path, tmp_path: Path) -> None:
    """WI-3 acceptance gate: stub-LLM eval suite produces byte-equal
    hypotheses.md + probe_directives.json across reruns (timestamps
    stripped — datetime.now drifts but the prose body is identical)."""
    case = load_case_file(case_file)
    runner = CuriosityEvalRunner()

    workspace_a = tmp_path / "a"
    workspace_b = tmp_path / "b"

    await runner.run(case, workspace=workspace_a)
    await runner.run(case, workspace=workspace_b)

    md_a = (workspace_a / "ws" / "hypotheses.md").read_text(encoding="utf-8")
    md_b = (workspace_b / "ws" / "hypotheses.md").read_text(encoding="utf-8")
    js_a = (workspace_b / "ws" / "probe_directives.json").read_text(encoding="utf-8")
    js_b = (workspace_b / "ws" / "probe_directives.json").read_text(encoding="utf-8")

    import re

    _ULID_RE = re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b")

    def _strip_volatile(text: str) -> str:
        """Strip lines + tokens that drift between runs: timestamps
        (datetime.now in the agent) and ULIDs (claim_ids minted fresh
        each run). The prose body — the actual rationale + statement
        content — must be byte-equal."""
        without_dates = "\n".join(
            line
            for line in text.splitlines()
            if "Scan window" not in line
            and "scan_completed_at" not in line
            and "emitted_at" not in line
        )
        return _ULID_RE.sub("<ULID>", without_dates)

    assert _strip_volatile(md_a) == _strip_volatile(md_b)
    assert _strip_volatile(js_a) == _strip_volatile(js_b)


# ---------------------------------------------------------------------------
# 10/10 acceptance gate (re-verified post-refactor)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_file",
    _all_case_files(),
    ids=lambda p: p.stem,
)
async def test_case_still_passes_after_stub_refactor(case_file: Path, tmp_path: Path) -> None:
    """All 10 cases must still pass when stub responses come from the
    new stub_responses/ layout instead of inline llm_responses."""
    case = load_case_file(case_file)
    runner = CuriosityEvalRunner()

    passed, failure_reason, _actuals, _audit_log = await runner.run(case, workspace=tmp_path)
    assert passed, f"{case.case_id} failed after stub refactor: {failure_reason}"
