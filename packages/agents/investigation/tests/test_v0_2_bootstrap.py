"""investigation v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the v0.1
contracts — and must preserve D.7's structured-LLM Orchestrator-Workers profile: FULL Charter +
ToolRegistry (worker tools via ctx.call_tool), OCSF 2005 emission (D.7 is the **sole** 2005
emitter), the **sub-agent allowlist `{"investigation"}`** (WI-I15 — Supervisor's H2 hierarchy),
and the H5 caps (depth <= 3, parallel <= 5). These guards fail loudly if a later task erodes
any of them, before the live-evidence / invariant surfaces are added.
"""

from __future__ import annotations

from pathlib import Path

import investigation
from investigation.orchestrator import (
    MAX_SUB_AGENT_DEPTH,
    MAX_SUB_AGENTS_PARALLEL,
    SUB_AGENT_ALLOWLIST,
)
from investigation.schemas import OCSF_CLASS_UID

_EVAL_DIR = Path(investigation.__file__).resolve().parents[2] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    assert investigation.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    import investigation.agent
    import investigation.orchestrator
    import investigation.schemas
    import investigation.synthesizer  # noqa: F401


def test_ocsf_class_uid_is_2005() -> None:
    """Q7 / WI-I5: D.7 emits OCSF Incident Finding class_uid 2005 (the sole 2005 emitter)."""
    assert OCSF_CLASS_UID == 2005


def test_sub_agent_allowlist_preserved() -> None:
    """WI-I15: only 'investigation' may spawn workers — Supervisor's H2 hierarchy is honored."""
    assert frozenset({"investigation"}) == SUB_AGENT_ALLOWLIST


def test_orchestrator_worker_caps() -> None:
    """Q1 / H5: depth <= 3, parallel <= 5 (formalized at code level in Task 17)."""
    assert MAX_SUB_AGENT_DEPTH == 3
    assert MAX_SUB_AGENTS_PARALLEL == 5


def test_full_charter_and_registry() -> None:
    """Deviation profile: D.7 is structured-LLM — full Charter wrap + a worker ToolRegistry."""
    from investigation.agent import build_registry

    src = (Path(investigation.__file__).resolve().parent / "agent.py").read_text(encoding="utf-8")
    assert "with Charter(" in src  # D.7 runs inside the charter (unlike the supervisor)
    assert "ctx.call_tool(" in src  # worker tools dispatched via the tool-proxy boundary
    assert build_registry is not None


def test_ten_eval_cases_present() -> None:
    assert len(list(_EVAL_DIR.glob("*.yaml"))) == 10
