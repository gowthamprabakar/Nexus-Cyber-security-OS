"""Tests — `meta_harness.tools.nlah_parser` (Task 3).

12 tests covering:

1.  Happy-path against a real shipped agent's NLAH dir (cloud_posture).
2.  Persona extracted from the README's first non-heading paragraph.
3.  Declared tools parsed from level-2 headers (cloud_posture).
4.  Example count matches files under `examples/`.
5.  Eval-case count from cross-referenced `eval/cases/*.yaml`.
6.  Optional pieces (no tools.md, no examples/, no eval_cases_dir).
7.  Missing NLAH directory raises ``NlahParseError``.
8.  Missing README.md raises ``NlahParseError``.
9.  Empty README.md raises ``NlahParseError``.
10. Synthetic NLAH dir under ``tmp_path`` round-trips.
11. Tool-name deduplication preserves first-occurrence order.
12. **WI-4 runtime guard** — ``Path.open`` and ``builtins.open``
    are monkey-patched while the parser runs; any non-read-mode
    invocation fails the test.
"""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest
from meta_harness.schemas import AgentManifest
from meta_harness.tools.nlah_parser import NlahParseError, parse_nlah_dir

_REPO_ROOT = Path(__file__).resolve().parents[4]
_CLOUD_POSTURE_NLAH = _REPO_ROOT / "packages/agents/cloud-posture/src/cloud_posture/nlah"
_CLOUD_POSTURE_CASES = _REPO_ROOT / "packages/agents/cloud-posture/eval/cases"


# ---------------------------------------------------------------------------
# Happy-path against the real cloud_posture NLAH dir
# ---------------------------------------------------------------------------


def test_real_agent_nlah_parses_to_manifest() -> None:
    manifest = parse_nlah_dir(
        _CLOUD_POSTURE_NLAH,
        agent_id="cloud_posture",
        eval_cases_dir=_CLOUD_POSTURE_CASES,
    )
    assert isinstance(manifest, AgentManifest)
    assert manifest.agent_id == "cloud_posture"
    assert manifest.persona, "persona must be non-empty for a shipped agent"
    assert manifest.declared_tools, "cloud_posture must declare ≥1 tool"
    assert manifest.example_count >= 2, "cloud_posture ships ≥2 examples"
    assert manifest.eval_case_count >= 5, "cloud_posture ships ≥5 eval cases"


def test_persona_is_first_non_heading_paragraph() -> None:
    manifest = parse_nlah_dir(_CLOUD_POSTURE_NLAH, agent_id="cloud_posture")
    assert not manifest.persona.startswith("#"), "persona must not start with a heading"
    assert "Cloud Posture" in manifest.persona


def test_declared_tools_parsed_from_real_tools_md() -> None:
    manifest = parse_nlah_dir(_CLOUD_POSTURE_NLAH, agent_id="cloud_posture")
    # The real cloud-posture tools.md declares prowler_scan + AWS SDK shims.
    assert "prowler_scan" in manifest.declared_tools


def test_example_count_matches_real_examples_dir() -> None:
    manifest = parse_nlah_dir(_CLOUD_POSTURE_NLAH, agent_id="cloud_posture")
    on_disk = sum(1 for p in (_CLOUD_POSTURE_NLAH / "examples").iterdir() if p.suffix == ".md")
    assert manifest.example_count == on_disk


def test_eval_case_count_matches_real_cases_dir() -> None:
    manifest = parse_nlah_dir(
        _CLOUD_POSTURE_NLAH,
        agent_id="cloud_posture",
        eval_cases_dir=_CLOUD_POSTURE_CASES,
    )
    on_disk = sum(1 for p in _CLOUD_POSTURE_CASES.iterdir() if p.suffix == ".yaml")
    assert manifest.eval_case_count == on_disk


def test_eval_case_count_zero_when_no_cases_dir_provided() -> None:
    manifest = parse_nlah_dir(_CLOUD_POSTURE_NLAH, agent_id="cloud_posture")
    assert manifest.eval_case_count == 0


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_missing_nlah_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(NlahParseError, match="NLAH directory missing"):
        parse_nlah_dir(tmp_path / "nope", agent_id="x")


def test_missing_readme_raises(tmp_path: Path) -> None:
    (tmp_path / "nlah").mkdir()
    with pytest.raises(NlahParseError, match=r"README\.md missing"):
        parse_nlah_dir(tmp_path / "nlah", agent_id="x")


def test_empty_readme_raises(tmp_path: Path) -> None:
    nlah = tmp_path / "nlah"
    nlah.mkdir()
    (nlah / "README.md").write_text("   \n\n", encoding="utf-8")
    with pytest.raises(NlahParseError, match="empty"):
        parse_nlah_dir(nlah, agent_id="x")


# ---------------------------------------------------------------------------
# Synthetic NLAH dir
# ---------------------------------------------------------------------------


def test_synthetic_nlah_round_trips(tmp_path: Path) -> None:
    nlah = tmp_path / "nlah"
    nlah.mkdir()
    (nlah / "README.md").write_text(
        "# Synthetic Agent\n\nYou are a synthetic agent for testing purposes.\n",
        encoding="utf-8",
    )
    (nlah / "tools.md").write_text(
        "# Tools\n\n## `do_thing(x, y)`\n\nDoes a thing.\n\n## `do_other(z)`\n\n",
        encoding="utf-8",
    )
    examples = nlah / "examples"
    examples.mkdir()
    (examples / "ex1.md").write_text("example 1", encoding="utf-8")
    (examples / "ex2.md").write_text("example 2", encoding="utf-8")
    cases = tmp_path / "eval" / "cases"
    cases.mkdir(parents=True)
    (cases / "c1.yaml").write_text("id: c1\n", encoding="utf-8")

    manifest = parse_nlah_dir(nlah, agent_id="synthetic", eval_cases_dir=cases)
    assert manifest.persona.startswith("You are a synthetic agent")
    assert manifest.declared_tools == ("do_thing", "do_other")
    assert manifest.example_count == 2
    assert manifest.eval_case_count == 1


def test_tool_name_dedup_preserves_first_occurrence(tmp_path: Path) -> None:
    nlah = tmp_path / "nlah"
    nlah.mkdir()
    (nlah / "README.md").write_text("# X\n\nA test agent.\n", encoding="utf-8")
    (nlah / "tools.md").write_text(
        "## `alpha(a)`\n\n## `beta(b)`\n\n## `alpha(a)`\n",
        encoding="utf-8",
    )
    manifest = parse_nlah_dir(nlah, agent_id="x")
    assert manifest.declared_tools == ("alpha", "beta")


# ---------------------------------------------------------------------------
# WI-4 runtime guard — Path.open + builtins.open must never receive a
# non-read mode while the parser runs.
# ---------------------------------------------------------------------------


def test_wi4_parser_never_opens_in_write_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """WI-4 acceptance — any non-read mode is treated as a v0.1 bug.

    The guard wraps ``Path.open`` and ``builtins.open`` and inspects
    the ``mode`` argument. ``read_text`` calls ``Path.open(mode='r')``
    internally, so a read-only parser produces only read-mode calls
    here. Any write mode (containing ``w``, ``a``, ``x``, or ``+``)
    fails the test.
    """
    read_only_modes = {"r", "rt", "rb"}
    observed_modes: list[str] = []

    original_path_open = Path.open
    original_builtins_open = builtins.open

    def _check_mode(mode: object) -> str:
        mode_str = mode if isinstance(mode, str) else "r"
        observed_modes.append(mode_str)
        forbidden = set("wax+")
        if any(ch in forbidden for ch in mode_str):
            raise AssertionError(
                f"WI-4 violation — parser attempted non-read open(mode={mode_str!r})"
            )
        return mode_str

    def patched_path_open(self: Path, mode: str = "r", *args: object, **kwargs: object) -> object:
        _check_mode(mode)
        return original_path_open(self, mode, *args, **kwargs)  # type: ignore[arg-type]

    def patched_builtins_open(
        file: object, mode: str = "r", *args: object, **kwargs: object
    ) -> object:
        _check_mode(mode)
        return original_builtins_open(file, mode, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", patched_path_open)
    monkeypatch.setattr(builtins, "open", patched_builtins_open)

    parse_nlah_dir(
        _CLOUD_POSTURE_NLAH,
        agent_id="cloud_posture",
        eval_cases_dir=_CLOUD_POSTURE_CASES,
    )

    assert observed_modes, "guard must observe at least one open call (README.md)"
    for mode in observed_modes:
        assert mode in read_only_modes or set(mode).issubset({"r", "t", "b"}), (
            f"WI-4 violation — observed non-read mode {mode!r}"
        )
