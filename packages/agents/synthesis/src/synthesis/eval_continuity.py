"""Stub-LLM eval continuity (synthesis v0.2 Task 12, Q6/WI-Y5).

Formalizes the two-lane eval discipline. The **stub-LLM** harness is the default, deterministic,
offline path — its OCSF emission is byte-identical across runs (WI-Y5), so the 10 eval cases
keep passing identically as v0.2 features land. The **live-LLM** lane (NEXUS_LIVE_SYNTHESIS) is
**separate**: capability validation, not byte-identity (an LLM's output varies run to run). This
module lets a test assert both properties without re-running the whole harness.
"""

from __future__ import annotations

from synthesis.live_lane import nexus_live_synthesis_enabled
from synthesis.ocsf.emission import build_synthesis_finding_json
from synthesis.schemas import SynthesisReport

#: The number of offline stub-LLM eval cases that must keep passing byte-identically.
STUB_EVAL_CASE_COUNT = 10


def stub_lane_active() -> bool:
    """The stub (deterministic) lane is active whenever the live lane is not enabled."""
    return not nexus_live_synthesis_enabled()


def stub_emission_is_byte_identical(report: SynthesisReport) -> bool:
    """WI-Y5: the stub path's OCSF emission is deterministic — the same report renders to the
    same bytes every time."""
    return build_synthesis_finding_json(report) == build_synthesis_finding_json(report)
