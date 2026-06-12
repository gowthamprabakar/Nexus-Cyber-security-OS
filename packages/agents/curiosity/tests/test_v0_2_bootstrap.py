"""curiosity v0.2 Task 1 — bootstrap + deviation-profile re-verification (Cycle 15)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import curiosity
from curiosity.agent import build_registry
from curiosity.schemas import CoverageGap, CuriosityClaim

_SRC = Path(curiosity.__file__).parent


def test_version_is_v0_2() -> None:
    assert curiosity.__version__ == "0.2.0"


def test_build_registry_is_empty() -> None:
    # WI-X12: D.12 deviation profile — empty ToolRegistry, no charter-gated tools.
    assert tuple(build_registry().known_tools()) == ()


def test_no_per_agent_llm_module() -> None:
    # WI-X12 / Cycle-13/14 lesson: LLM only via charter.llm; the v0.2 provider wrapper
    # goes under curiosity/providers/, never a curiosity.llm namespace.
    assert importlib.util.find_spec("curiosity.llm") is None


def test_llm_via_charter() -> None:
    src = (_SRC / "agent.py").read_text()
    assert "from charter.llm import LLMProvider" in src


def test_ten_stub_eval_cases_present() -> None:
    # WI-X5: the OCSF 2004 baseline is established against the existing 10 stub eval cases.
    eval_root = _SRC.parents[1] / "eval" / "stub_responses"
    cases = [p for p in eval_root.iterdir() if p.is_dir()]
    assert len(cases) == 10


def test_claims_envelope_importable() -> None:
    # CuriosityClaim continues on claims.> (additive OCSF 2004 lands in M2).
    assert CuriosityClaim is not None
    assert CoverageGap is not None
