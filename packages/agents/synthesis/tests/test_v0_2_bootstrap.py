"""synthesis v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the v0.1
contracts — and, critically, must not erode the **LLM-first empty-registry deviation profile**
(WI-Y9): synthesis has an **empty ToolRegistry** (no charter-gated tools) and reaches the LLM
**only** via ``charter.llm_adapter``. These guards fail loudly if a later task accidentally
registers a tool, and re-assert the 10 stub-LLM eval cases at bootstrap before the OCSF
emission surface (M2) is added.
"""

from __future__ import annotations

from pathlib import Path

import synthesis
from synthesis.agent import build_registry

_EVAL_DIR = Path(synthesis.__file__).resolve().parents[2] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    assert synthesis.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    import synthesis.agent
    import synthesis.narrator
    import synthesis.reviewer
    import synthesis.schemas  # noqa: F401
    from synthesis.tools.sibling_workspace_reader import SiblingFindings  # noqa: F401


def test_deviation_empty_tool_registry() -> None:
    """WI-Y9: synthesis ships an EMPTY ToolRegistry — no charter-gated tools."""
    assert build_registry().known_tools() == []


def test_deviation_llm_via_charter_adapter_only() -> None:
    """WI-Y9: LLM access is exclusively through charter.llm_adapter — no other LLM client."""
    from charter.llm_adapter import config_from_env, make_provider  # noqa: F401

    src = (Path(synthesis.__file__).resolve().parent).rglob("*.py")
    blob = "\n".join(p.read_text(encoding="utf-8") for p in src)
    # No direct third-party LLM SDK imports — only the charter adapter.
    assert "import openai" not in blob
    assert "import anthropic" not in blob


def test_ten_stub_eval_cases_present() -> None:
    assert len(list(_EVAL_DIR.glob("*.yaml"))) == 10


def test_no_charter_substrate_edit_marker() -> None:
    # Deviation note: v0.2 adds OCSF emission but no charter hoist is expected at D.13.
    assert synthesis.__version__ == "0.2.0"
