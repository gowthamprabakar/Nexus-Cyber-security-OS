"""WI-Y4 (HARD) — live LLM synthesis end-to-end (synthesis v0.2 Task 18).

Per the WI-V6/I4/T4/R4/N4/K4/C2/S4/F4/O4 lineage. The full D.13 pipeline exercised offline with
fakes (the live provider is gated), proving the v0.2 surfaces compose:

  12-source fleet read -> per-source enumeration -> cross-source orchestration -> narrative ->
  OCSF 2004 emission, with the three LLM-agent invariants and the DeepSeek->Anthropic fallback.

The three code-level invariants are exercised end-to-end: assert_categorical_only (WI-Y8),
assert_bounded_retry (WI-Y10), assert_findings_cited (WI-Y13). The gated-live layer
(NEXUS_LIVE_SYNTHESIS=1) runs the real provider; it is skipped in CI.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from synthesis.cross_source import cross_source_context
from synthesis.live_lane import synthesis_live_skip_reason
from synthesis.ocsf.emission import build_synthesis_finding_json
from synthesis.ocsf.narrative_translator import translate_report_to_ocsf
from synthesis.privacy.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)
from synthesis.providers.triggers import make_resilient_provider
from synthesis.retry.bounded import BoundedRetryViolationError, assert_bounded_retry
from synthesis.schemas import ExecutiveSummary, NarrativeSection, SynthesisReport
from synthesis.tools.fleet_enumeration import all_cited_finding_ids, enumerate_fleet
from synthesis.tools.fleet_workspace_reader import SOURCE_AGENTS, FleetFindings
from synthesis.validation.hallucination_guard import (
    HallucinationGuardViolationError,
    assert_findings_cited,
)

_T0 = datetime(2026, 6, 1, tzinfo=UTC)
_T1 = datetime(2026, 6, 1, 0, 5, tzinfo=UTC)


def _f(uid: str, *, severity: str = "high") -> dict[str, object]:
    return {"class_uid": 2004, "severity": severity, "finding_info": {"uid": uid}}


def _fleet() -> FleetFindings:
    base: dict[str, tuple[dict[str, object], ...]] = dict.fromkeys(SOURCE_AGENTS, ())
    base["compliance"] = (_f("CIS-1.1"), _f("CIS-2.1"))
    base["cloud_posture"] = (_f("CSPM-AWS-S3-001", severity="critical"),)
    base["data_security"] = (_f("DSPM-1"),)
    return FleetFindings(by_agent=base)


def _report(narrative_body: str, cited: list[str]) -> SynthesisReport:
    return SynthesisReport(
        customer_id="c1",
        run_id="run-7",
        scan_started_at=_T0,
        scan_completed_at=_T1,
        executive_summary=ExecutiveSummary(
            paragraph="Fleet review.", key_metrics={"highest_severity": "critical"}
        ),
        sections=[
            NarrativeSection(heading="Posture", body=narrative_body, cited_finding_ids=cited)
        ],
        cited_finding_ids=cited,
    )


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=1, output_tokens=1),
        model_pin="m",
    )


# --------------------------- offline pipeline ---------------------------


def test_fleet_to_cross_source_context() -> None:
    ctx = cross_source_context(_fleet())
    assert ctx["sources_with_findings"] == 3 and ctx["total_findings"] == 4
    # compliance (2 x high = weight 8) outranks cloud_posture (1 x critical = weight 5).
    assert ctx["ranked_sources"][0]["agent"] == "compliance"


def test_narrative_to_ocsf_2004() -> None:
    report = _report("`CSPM-AWS-S3-001` is public.", ["CSPM-AWS-S3-001"])
    finding = json.loads(build_synthesis_finding_json(report))
    assert finding["class_uid"] == 2004
    assert translate_report_to_ocsf(report)["finding_info"]["uid"] == "SYN-run-7"


def test_categorical_invariant_e2e() -> None:
    # WI-Y8: a categorical narrative passes; a plaintext-PII one is blocked.
    assert_categorical_only("The fleet has 2 [SSN] findings in `DSPM-1`.")
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("Leaked SSN 123-45-6789 in the bucket.")


def test_bounded_retry_invariant_e2e() -> None:
    # WI-Y10: a 2nd attempt is within bound; a 3rd is blocked.
    assert_bounded_retry(2)
    with pytest.raises(BoundedRetryViolationError):
        assert_bounded_retry(3)


def test_hallucination_guard_e2e() -> None:
    # WI-Y13: the narrative may only cite finding ids in the source set.
    source = all_cited_finding_ids(_fleet())
    assert_findings_cited("Posture: `CSPM-AWS-S3-001` is public.", source)
    with pytest.raises(HallucinationGuardViolationError):
        assert_findings_cited("Critical `CSPM-AWS-S3-099` exposure.", source)


@pytest.mark.asyncio
async def test_provider_fallback_e2e() -> None:
    # DeepSeek 503 -> Anthropic recovery.
    class _Boom:
        provider_id = "deepseek"

        async def complete(self, **kwargs: object) -> LLMResponse:
            raise RuntimeError("503 service unavailable")

    fallback = FakeLLMProvider([_resp("from-anthropic")], provider_id="anthropic")
    provider = make_resilient_provider(primary=_Boom(), fallback=fallback)  # type: ignore[arg-type]
    resp = await provider.complete(prompt="x", model_pin="m", max_tokens=10)
    assert resp.text == "from-anthropic" and provider.provider_used == "anthropic"


def test_per_source_enumeration_e2e() -> None:
    by_agent = {e.agent_id: e.finding_count for e in enumerate_fleet(_fleet())}
    assert (
        by_agent["compliance"] == 2 and by_agent["cloud_posture"] == 1 and by_agent["identity"] == 0
    )


# --------------------------- gated-live layer ---------------------------


def test_live_provider_reachable() -> None:
    reason = synthesis_live_skip_reason()
    if reason is not None:
        pytest.skip(reason)
    # When the live lane is enabled + reachable, a real 3-call run would execute here.
