"""Tests — ``data_security.nlah_loader`` (ADR-007 v1.2 shim conformance).

Task 13. Verifies:

- The shim file itself is ≤ 35 LOC (ADR-007 v1.2 budget).
- ``default_nlah_dir()`` resolves to a real directory containing the
  bundled NLAH files.
- ``load_system_prompt()`` returns non-empty text with the agent
  identifier present.
- The 3 expected NLAH files exist (README.md, tools.md, 2 examples).
- The NLAH README mentions the Q6 privacy contract (load-bearing).
"""

from __future__ import annotations

import inspect
from pathlib import Path

from data_security.nlah_loader import default_nlah_dir, load_system_prompt


def test_shim_loc_budget_under_35() -> None:
    """ADR-007 v1.2: the per-agent shim must be ≤ 35 LOC.

    Trivial constants + delegating wrappers — the substrate work lives in
    ``charter.nlah_loader``.
    """
    import data_security.nlah_loader as shim_module

    source = inspect.getsource(shim_module)
    # Count non-empty lines (ignore blank lines so the budget is about
    # actual semantic content).
    non_blank = [ln for ln in source.splitlines() if ln.strip()]
    assert len(non_blank) <= 35, (
        f"data_security.nlah_loader is {len(non_blank)} non-blank lines; "
        "ADR-007 v1.2 budget is ≤ 35."
    )


def test_default_nlah_dir_resolves_to_package_directory() -> None:
    nlah_dir = default_nlah_dir()
    assert isinstance(nlah_dir, Path)
    assert nlah_dir.exists()
    assert nlah_dir.is_dir()
    assert nlah_dir.name == "nlah"


def test_bundled_nlah_files_exist() -> None:
    """ADR-007 v1.2: README + tools.md + ≥ 2 examples shipped inside the package."""
    nlah_dir = default_nlah_dir()
    assert (nlah_dir / "README.md").is_file()
    assert (nlah_dir / "tools.md").is_file()
    examples_dir = nlah_dir / "examples"
    assert examples_dir.is_dir()
    examples = sorted(examples_dir.glob("*.md"))
    assert len(examples) >= 2, f"expected ≥ 2 NLAH examples, got {len(examples)}"


def test_load_system_prompt_returns_non_empty_text() -> None:
    prompt = load_system_prompt()
    assert isinstance(prompt, str)
    assert len(prompt) > 0
    # Agent identifier surfaces in the prompt.
    assert "Data Security Agent" in prompt
    # ADR-007 chain reference present.
    assert "ADR-007" in prompt


def test_load_system_prompt_accepts_explicit_dir() -> None:
    """The loader accepts an optional explicit path override."""
    prompt = load_system_prompt(default_nlah_dir())
    assert "Data Security Agent" in prompt


def test_nlah_readme_mentions_q6_privacy_contract() -> None:
    """Q6 is load-bearing. The NLAH README MUST mention it so the agent's
    operating brain carries the invariant.
    """
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "Q6" in readme or "PRIVACY CONTRACT" in readme.upper()


def test_nlah_readme_mentions_seven_stage_pipeline() -> None:
    """The 7-stage pipeline must be documented in the NLAH so the agent's
    operating brain knows the sequence.
    """
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    for stage in ("INGEST", "CLASSIFY", "DETECT", "CORRELATE", "SCORE", "SUMMARIZE", "HANDOFF"):
        assert stage in readme, f"NLAH README missing stage {stage}"


def test_tools_md_lists_all_detectors() -> None:
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    for detector in (
        "detect_public_bucket",
        "detect_unencrypted",
        "detect_sensitive_location",
        "detect_oversharing_iam",
    ):
        assert detector in tools, f"tools.md missing {detector}"
